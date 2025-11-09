package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/lib/pq"
)

var (
	// --- Postgres (updated defaults for dev-r2) ---
	dbURL = envOr("DATABASE_URL", "postgres://authportal:change-me@postgres:5432/authportaldb?sslmode=disable")

	// --- LDAP (updated defaults for dev-r2) ---
	// Supports ldap:// or ldaps://
	ldapHost     = envOr("LDAP_HOST", "ldap://openldap:389")
	ldapAdminDN  = envOr("LDAP_ADMIN_DN", "cn=admin,dc=authportal,dc=local")
	ldapPassword = envOr("LDAP_ADMIN_PASSWORD", "")
	// Base OU for users, e.g. "ou=users,dc=authportal,dc=local"
	baseDN   = envOr("BASE_DN", "ou=users,dc=authportal,dc=local")
	startTLS = strings.EqualFold(envOr("LDAP_STARTTLS", "false"), "true")

	// Timeouts
	dbTimeout   = 8 * time.Second
	ldapTimeout = 10 * time.Second
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Matches dev-r2 DB schema (media_* fields)
type rowUser struct {
	Username    string
	Email       sql.NullString
	MediaUUID   sql.NullString
	MediaAccess bool // not scanned directly; filtered in SQL
}

type identityInfo struct {
	Provider  string
	MediaUUID string
}

type syncUser struct {
	Username string
	Email    sql.NullString
	idents   map[string]identityInfo
}

func (u *syncUser) addIdentity(provider, mediaUUID string) {
	if u == nil {
		return
	}
	provider = strings.TrimSpace(provider)
	mediaUUID = strings.TrimSpace(mediaUUID)
	if provider == "" && mediaUUID == "" {
		return
	}
	if u.idents == nil {
		u.idents = make(map[string]identityInfo)
	}
	key := provider + "\x00" + mediaUUID
	if _, exists := u.idents[key]; exists {
		return
	}
	u.idents[key] = identityInfo{
		Provider:  provider,
		MediaUUID: mediaUUID,
	}
}

func (u *syncUser) identityList() []identityInfo {
	if u == nil || len(u.idents) == 0 {
		return nil
	}
	out := make([]identityInfo, 0, len(u.idents))
	for _, info := range u.idents {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].MediaUUID < out[j].MediaUUID
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func normalizeNullString(ns sql.NullString) sql.NullString {
	if !ns.Valid {
		return sql.NullString{}
	}
	trimmed := strings.TrimSpace(ns.String)
	if trimmed == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

func main() {
	// ---- Postgres
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("postgres open: %v", err)
	}
	defer db.Close()

	{
		ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("postgres ping: %v", err)
		}
	}

	// Prefer identities (multi-provider) when available; fallback to legacy users
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	var identitiesAvailable bool
	if err := db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
      FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = 'identities'
)`).Scan(&identitiesAvailable); err != nil {
		log.Fatalf("identities table check: %v", err)
	}

	var (
		rows          *sql.Rows
		queryErr      error
		useIdentities bool
	)

	if identitiesAvailable {
		rows, queryErr = db.QueryContext(ctx, `
SELECT u.username, u.email, i.media_uuid, i.provider
  FROM identities i
  JOIN users u ON u.id = i.user_id
 WHERE i.media_access = TRUE
 ORDER BY u.username, i.provider`)
		if queryErr != nil {
			log.Printf("identities query failed (falling back to legacy users): %v", queryErr)
		} else {
			useIdentities = true
		}
	}

	if rows == nil {
		rows, queryErr = db.QueryContext(ctx, `
SELECT username, email, media_uuid
  FROM users
 WHERE media_access = TRUE
 ORDER BY username`)
		if queryErr != nil {
			log.Fatalf("query users: %v", queryErr)
		}
	}
	defer rows.Close()

	users := make(map[string]*syncUser)

	for rows.Next() {
		var (
			username  string
			email     sql.NullString
			mediaUUID sql.NullString
			provider  string
		)
		if useIdentities {
			if err := rows.Scan(&username, &email, &mediaUUID, &provider); err != nil {
				log.Printf("scan row (identities): %v", err)
				continue
			}
		} else {
			if err := rows.Scan(&username, &email, &mediaUUID); err != nil {
				log.Printf("scan row (users): %v", err)
				continue
			}
			provider = inferProviderFromUUID(mediaUUID.String)
		}

		username = strings.TrimSpace(username)
		if username == "" {
			log.Println("skipping user with empty username")
			continue
		}

		entry, ok := users[username]
		if !ok {
			entry = &syncUser{Username: username}
			users[username] = entry
		}

		if normEmail := normalizeNullString(email); normEmail.Valid {
			if !entry.Email.Valid || entry.Email.String == "" {
				entry.Email = normEmail
			}
		}

		entry.addIdentity(provider, mediaUUID.String)
	}
	if err := rows.Err(); err != nil {
		log.Printf("rows error: %v", err)
	}

	// ---- LDAP connect & bind
	l, err := dialLDAP(ldapHost)
	if err != nil {
		log.Fatalf("LDAP connect error: %v", err)
	}
	defer l.Close()

	if startTLS {
		if err := l.StartTLS(nil); err != nil {
			log.Fatalf("LDAP StartTLS error: %v", err)
		}
	}

	if err := l.Bind(ldapAdminDN, ldapPassword); err != nil {
		log.Fatalf("LDAP bind error: %v", err)
	}

	// Ensure base OU exists, create it if needed
	if err := ensureOUExists(l, baseDN); err != nil {
		log.Fatalf("ensureOUExists(%s): %v", baseDN, err)
	}
	// Process aggregated users
	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	for _, username := range usernames {
		entry := users[username]

		// Build DN
		userDN := fmt.Sprintf("uid=%s,%s", ldapEscape(username), baseDN)

		// Read existing entry (if any)
		exists, err := entryExists(l, baseDN, username)
		if err != nil {
			log.Printf("LDAP search error for %s: %v", username, err)
			continue
		}

		// Build auxiliary attributes
		mailVals := []string{}
		if entry.Email.Valid {
			mailVals = append(mailVals, entry.Email.String)
		}
		descVals := []string{}
		for _, ident := range entry.identityList() {
			if ident.Provider != "" {
				descVals = append(descVals, "provider="+ident.Provider)
			}
			if ident.MediaUUID != "" {
				descVals = append(descVals, "media_uuid="+ident.MediaUUID)
			}
		}

		if !exists {
			// Add new inetOrgPerson (include standard aux classes for compatibility)
			addReq := ldap.NewAddRequest(userDN, nil)
			addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
			addReq.Attribute("uid", []string{username})
			addReq.Attribute("cn", []string{username})
			addReq.Attribute("sn", []string{"User"})
			if len(mailVals) > 0 {
				addReq.Attribute("mail", mailVals)
			}
			if len(descVals) > 0 {
				addReq.Attribute("description", descVals)
			}
			// Optionally set a placeholder password or omit entirely:
			// addReq.Attribute("userPassword", []string{"{SSHA}placeholder"})

			if err := l.Add(addReq); err != nil {
				log.Printf("LDAP add %s: %v", userDN, err)
				continue
			}
			log.Printf("LDAP added: %s", userDN)
			continue
		}

		// Modify existing
		modReq := ldap.NewModifyRequest(userDN, nil)
		// Replace/ensure required attributes
		modReq.Replace("cn", []string{username})
		modReq.Replace("sn", []string{"User"})
		modReq.Replace("uid", []string{username})

		// Optional fields
		modReq.Replace("mail", mailVals)        // empty slice clears attribute
		modReq.Replace("description", descVals) // store media_uuid for reference

		if err := l.Modify(modReq); err != nil {
			log.Printf("LDAP modify %s: %v", userDN, err)
			continue
		}
		log.Printf("LDAP updated: %s", userDN)
	}
}

// dialLDAP supports ldap:// and ldaps://, or host:port (plain)
func dialLDAP(host string) (*ldap.Conn, error) {
	d := &net.Dialer{Timeout: ldapTimeout}
	if strings.HasPrefix(host, "ldap://") || strings.HasPrefix(host, "ldaps://") {
		return ldap.DialURL(host, ldap.DialWithDialer(d))
	}
	return ldap.DialURL("ldap://"+host, ldap.DialWithDialer(d))
}

// --- helpers ---

// ensureOUExists creates the OU branch if missing.
// Supports either "ou=users,dc=..." or "dc=a,dc=b" base with an OU under it.
func ensureOUExists(l *ldap.Conn, base string) error {
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "ou=") {
		exists, err := dnExists(l, base)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		add := ldap.NewAddRequest(base, nil)
		add.Attribute("objectClass", []string{"top", "organizationalUnit"})
		if ou := firstRDNValue(lower, "ou"); ou != "" {
			add.Attribute("ou", []string{ou})
		}
		return l.Add(add)
	}

	target := fmt.Sprintf("ou=users,%s", base)
	exists, err := dnExists(l, target)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	add := ldap.NewAddRequest(target, nil)
	add.Attribute("objectClass", []string{"top", "organizationalUnit"})
	add.Attribute("ou", []string{"users"})
	return l.Add(add)
}

func dnExists(l *ldap.Conn, dn string) (bool, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, err
	}
	return len(res.Entries) > 0, nil
}

func entryExists(l *ldap.Conn, base, username string) (bool, error) {
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(uid=%s)", ldapEscape(username)),
		[]string{"dn"},
		nil,
	)
	res, err := l.Search(req)
	if err != nil {
		return false, err
	}
	return len(res.Entries) > 0, nil
}

// ldapEscape is a minimal DN/Filter value escape for uid usage in filters/DNs.
func ldapEscape(s string) string {
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)
	return replacer.Replace(s)
}

func firstRDNValue(dnLower, key string) string {
	parts := strings.Split(dnLower, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(p, key+"="))
		}
	}
	return ""
}

// inferProviderFromUUID returns provider based on a media_uuid prefix.
func inferProviderFromUUID(u string) string {
	s := strings.ToLower(strings.TrimSpace(u))
	switch {
	case strings.HasPrefix(s, "plex-"):
		return "plex"
	case strings.HasPrefix(s, "emby-"):
		return "emby"
	case strings.HasPrefix(s, "jellyfin-"):
		return "jellyfin"
	default:
		return ""
	}
}
