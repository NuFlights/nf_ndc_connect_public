use serde::{Deserialize, Serialize};

// =============================================================================
//  CASDOOR JWT STRUCTS
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorRole {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub is_enabled: bool,
}

impl CasdoorRole {
    /// Returns the fully-qualified role reference: `{owner}/{name}`
    #[inline]
    pub fn qualified_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorPermission {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    #[serde(default)]
    pub is_enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorClaims {
    // --- User identity ---
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub id_card: String,
    #[serde(default, rename = "type")]
    pub user_type: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,

    // --- Admin flags ---
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub is_global_admin: bool,
    #[serde(default)]
    pub is_forbidden: bool,
    #[serde(default)]
    pub is_deleted: bool,

    // --- RBAC ---
    #[serde(default)]
    pub roles: Vec<CasdoorRole>,
    #[serde(default)]
    pub permissions: Vec<CasdoorPermission>,
}

// =============================================================================
//  OUTPUT STRUCTURES
// =============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupAuthSummary {
    pub org_short_code: String,
    pub role: String,
    pub permissions: Vec<String>,
}

// =============================================================================
//  CASDOOR USER (Context Object)
// =============================================================================

/// This struct holds the parsed state. It is returned by AuthHelper::validate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CasdoorUser {
    pub claims: CasdoorClaims,
    pub summaries: Vec<GroupAuthSummary>,
}

impl CasdoorUser {
    pub fn new(claims: CasdoorClaims) -> Result<Self, String> {
        let summaries = Self::compute_summaries(&claims)?;
        Ok(Self { claims, summaries })
    }

    /// Internal logic to pre-calculate the authentication summaries.
    fn compute_summaries(claims: &CasdoorClaims) -> Result<Vec<GroupAuthSummary>, String> {
        let mut summaries = Vec::new();

        for role in &claims.roles {
            // Skip disabled roles
            if !role.is_enabled {
                continue;
            }

            if role.groups.is_empty() {
                return Err(format!(
                    "Role '{}' has no group association; at least 1 is required",
                    role.name
                ));
            }

            let qualified_role = role.qualified_name();

            // Pre-compute permissions for this role once (shared across all groups)
            let perm_names: Vec<String> = claims
                .permissions
                .iter()
                .filter(|p| {
                    p.is_enabled
                        && p.roles.as_ref().is_some_and(|perm_roles| {
                            perm_roles
                                .iter()
                                .any(|role_ref| role_ref == &qualified_role)
                        })
                })
                .map(|p| p.name.clone())
                .collect();

            // Iterate ALL groups for this role
            for group in &role.groups {
                let org_short_code = group
                    .split_once('/')
                    .map(|(_, name)| name.to_string())
                    .ok_or_else(|| {
                        format!(
                            "Group '{}' is not fully qualified (expected '{{owner}}/{{name}}')",
                            group
                        )
                    })?;

                summaries.push(GroupAuthSummary {
                    org_short_code,
                    role: role.name.clone(),
                    permissions: perm_names.clone(),
                });
            }
        }
        Ok(summaries)
    }

    // -------------------------------------------------------------------------
    //  Group resolution helper (DRY)
    // -------------------------------------------------------------------------

    /// Resolves summaries for the given group_name.
    /// - If `group_name` is provided, returns all summaries matching that group.
    /// - If `None` and exactly 1 distinct org exists, returns all summaries for that org.
    /// - Otherwise, errors with an ambiguity message.
    fn resolve_summaries(&self, group_name: Option<&str>) -> Result<Vec<&GroupAuthSummary>, String> {
        match group_name {
            Some(g) => {
                let matches: Vec<&GroupAuthSummary> = self
                    .summaries
                    .iter()
                    .filter(|s| s.org_short_code == g)
                    .collect();
                if matches.is_empty() {
                    Err(format!("No summary found for group '{}'", g))
                } else {
                    Ok(matches)
                }
            }
            None => {
                let mut distinct_orgs: Vec<&str> = self
                    .summaries
                    .iter()
                    .map(|s| s.org_short_code.as_str())
                    .collect();
                distinct_orgs.sort();
                distinct_orgs.dedup();

                if distinct_orgs.len() == 1 {
                    Ok(self.summaries.iter().collect())
                } else if distinct_orgs.is_empty() {
                    Err("No group summaries available".into())
                } else {
                    Err(format!(
                        "Ambiguous: user belongs to {} groups; specify group_name explicitly",
                        distinct_orgs.len()
                    ))
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    //  Query methods
    // -------------------------------------------------------------------------

    /// Check if user belongs to a group.
    pub fn has_group(&self, group_name: &str) -> bool {
        self.summaries
            .iter()
            .any(|s| s.org_short_code == group_name)
    }

    /// Check if user has a role. If `group_name` is `None`, infer the default
    /// group (only when exactly 1 distinct org exists).
    pub fn has_role(&self, role_name: &str, group_name: Option<&str>) -> Result<bool, String> {
        let summaries = self.resolve_summaries(group_name)?;
        Ok(summaries.iter().any(|s| s.role == role_name))
    }

    /// Check if user has a single permission.
    pub fn has_permission(
        &self,
        perm_name: &str,
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let summaries = self.resolve_summaries(group_name)?;
        Ok(summaries
            .iter()
            .any(|s| s.permissions.iter().any(|p| p == perm_name)))
    }

    /// Check if user has ALL provided permissions (exhaustive).
    /// Checks the union of permissions across all summaries for the group.
    pub fn has_permissions(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let summaries = self.resolve_summaries(group_name)?;
        Ok(perm_names.iter().all(|name| {
            summaries
                .iter()
                .any(|s| s.permissions.iter().any(|p| p == name))
        }))
    }

    /// Check if user has ANY of the provided permissions (existential).
    pub fn has_permissions_any(
        &self,
        perm_names: &[String],
        group_name: Option<&str>,
    ) -> Result<bool, String> {
        let summaries = self.resolve_summaries(group_name)?;
        Ok(perm_names.iter().any(|name| {
            summaries
                .iter()
                .any(|s| s.permissions.iter().any(|p| p == name))
        }))
    }

    pub fn is_admin(&self) -> bool {
        self.claims.is_admin
    }

    pub fn is_global_admin(&self) -> bool {
        self.claims.is_global_admin
    }

    pub fn get_org_count(&self) -> usize {
        let mut orgs: Vec<&str> = self
            .summaries
            .iter()
            .map(|s| s.org_short_code.as_str())
            .collect();
        orgs.sort();
        orgs.dedup();
        orgs.len()
    }

    pub fn get_first_org_short_code(&self) -> Option<String> {
        self.summaries.first().map(|s| s.org_short_code.clone())
    }

    pub fn username(&self) -> String {
        self.claims.name.clone()
    }

    pub fn email(&self) -> Option<String> {
        self.claims.email.clone()
    }

    pub fn dj_id(&self) -> String {
        self.claims.id_card.clone()
    }

    pub fn get_org_short_codes(&self) -> Vec<String> {
        let mut codes: Vec<String> = self
            .summaries
            .iter()
            .map(|s| s.org_short_code.clone())
            .collect();
        codes.sort();
        codes.dedup();
        codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_role(name: &str, groups: Vec<&str>, enabled: bool) -> CasdoorRole {
        CasdoorRole {
            owner: "test_org".into(),
            name: name.into(),
            groups: groups.into_iter().map(|g| g.to_string()).collect(),
            is_enabled: enabled,
            ..Default::default()
        }
    }

    fn make_permission(name: &str, roles: Vec<&str>, enabled: bool) -> CasdoorPermission {
        CasdoorPermission {
            owner: "test_org".into(),
            name: name.into(),
            roles: Some(roles.into_iter().map(|r| r.to_string()).collect()),
            is_enabled: enabled,
            ..Default::default()
        }
    }

    #[test]
    fn test_multiple_groups_per_role() {
        let claims = CasdoorClaims {
            roles: vec![make_role(
                "admin",
                vec!["test_org/GroupA", "test_org/GroupB"],
                true,
            )],
            permissions: vec![make_permission("read", vec!["test_org/admin"], true)],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert_eq!(user.summaries.len(), 2);
        assert_eq!(user.summaries[0].org_short_code, "GroupA");
        assert_eq!(user.summaries[1].org_short_code, "GroupB");
        assert!(user.summaries[0].permissions.contains(&"read".to_string()));
        assert!(user.summaries[1].permissions.contains(&"read".to_string()));
    }

    #[test]
    fn test_disabled_role_skipped() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("active_role", vec!["test_org/GroupA"], true),
                make_role("disabled_role", vec!["test_org/GroupB"], false),
            ],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert_eq!(user.summaries.len(), 1);
        assert_eq!(user.summaries[0].role, "active_role");
    }

    #[test]
    fn test_role_with_no_groups_errors() {
        let claims = CasdoorClaims {
            roles: vec![make_role("orphan", vec![], true)],
            permissions: vec![],
            ..Default::default()
        };
        let result = CasdoorUser::new(claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no group association"));
    }

    #[test]
    fn test_disabled_role_with_no_groups_ok() {
        // A disabled role with no groups should be silently skipped, not error
        let claims = CasdoorClaims {
            roles: vec![make_role("disabled_orphan", vec![], false)],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert_eq!(user.summaries.len(), 0);
    }

    #[test]
    fn test_has_role_multi_summary_same_org() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgX"], true),
                make_role("viewer", vec!["test_org/OrgX"], true),
            ],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert!(user.has_role("admin", Some("OrgX")).unwrap());
        assert!(user.has_role("viewer", Some("OrgX")).unwrap());
        assert!(!user.has_role("editor", Some("OrgX")).unwrap());
    }

    #[test]
    fn test_has_permission_across_roles_same_org() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgX"], true),
                make_role("viewer", vec!["test_org/OrgX"], true),
            ],
            permissions: vec![
                make_permission("write", vec!["test_org/admin"], true),
                make_permission("read", vec!["test_org/viewer"], true),
            ],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert!(user.has_permission("write", Some("OrgX")).unwrap());
        assert!(user.has_permission("read", Some("OrgX")).unwrap());
        assert!(!user.has_permission("delete", Some("OrgX")).unwrap());
    }

    #[test]
    fn test_has_permissions_union_across_roles() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgX"], true),
                make_role("viewer", vec!["test_org/OrgX"], true),
            ],
            permissions: vec![
                make_permission("write", vec!["test_org/admin"], true),
                make_permission("read", vec!["test_org/viewer"], true),
            ],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        // "write" from admin + "read" from viewer should both be found
        assert!(user
            .has_permissions(
                &["write".to_string(), "read".to_string()],
                Some("OrgX")
            )
            .unwrap());
    }

    #[test]
    fn test_get_org_count_deduplicates() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgX"], true),
                make_role("viewer", vec!["test_org/OrgX"], true),
            ],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        // Two summaries but one distinct org
        assert_eq!(user.summaries.len(), 2);
        assert_eq!(user.get_org_count(), 1);
    }

    #[test]
    fn test_get_org_short_codes_deduplicates() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgX", "test_org/OrgY"], true),
                make_role("viewer", vec!["test_org/OrgX"], true),
            ],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        let codes = user.get_org_short_codes();
        assert_eq!(codes, vec!["OrgX", "OrgY"]);
    }

    #[test]
    fn test_ambiguous_group_requires_explicit() {
        let claims = CasdoorClaims {
            roles: vec![
                make_role("admin", vec!["test_org/OrgA"], true),
                make_role("viewer", vec!["test_org/OrgB"], true),
            ],
            permissions: vec![],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert!(user.has_role("admin", None).is_err());
        assert!(user.has_role("admin", Some("OrgA")).unwrap());
    }

    #[test]
    fn test_single_org_auto_resolves() {
        let claims = CasdoorClaims {
            roles: vec![make_role("admin", vec!["test_org/OrgA"], true)],
            permissions: vec![make_permission("read", vec!["test_org/admin"], true)],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert!(user.has_role("admin", None).unwrap());
        assert!(user.has_permission("read", None).unwrap());
    }

    #[test]
    fn test_disabled_permission_not_included() {
        let claims = CasdoorClaims {
            roles: vec![make_role("admin", vec!["test_org/OrgA"], true)],
            permissions: vec![
                make_permission("read", vec!["test_org/admin"], true),
                make_permission("write", vec!["test_org/admin"], false),
            ],
            ..Default::default()
        };
        let user = CasdoorUser::new(claims).unwrap();
        assert!(user.has_permission("read", None).unwrap());
        assert!(!user.has_permission("write", None).unwrap());
    }
}
