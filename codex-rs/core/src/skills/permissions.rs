use crate::bash::parse_shell_lc_plain_commands;
use crate::bash::parse_shell_lc_single_command_prefix;
use crate::protocol::SandboxPolicy;
use crate::skills::SkillMetadata;
use crate::skills::SkillPermissions;
use codex_utils_absolute_path::AbsolutePathBuf;
use dunce::canonicalize as canonicalize_path;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

const KNOWN_SCRIPT_INTERPRETERS: [&str; 9] = [
    "python", "python3", "bash", "sh", "zsh", "node", "ruby", "perl", "php",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillPermissionProfile {
    pub(crate) id: String,
    pub(crate) skill_name: String,
    pub(crate) skill_path: PathBuf,
    pub(crate) permissions: SkillPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillPermissionRule {
    pub(crate) pattern: Vec<String>,
    pub(crate) profile_id: String,
    pub(crate) script_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SkillPermissionRegistry {
    profiles: HashMap<String, Arc<SkillPermissionProfile>>,
    rules: Vec<SkillPermissionRule>,
    script_to_profile_id: HashMap<PathBuf, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkillPermissionContext {
    pub(crate) profile_id: String,
    pub(crate) reason: String,
    pub(crate) sandbox_policy_override: SandboxPolicy,
}

pub(crate) fn build_skill_permission_registry(
    mentioned_skills: &[SkillMetadata],
) -> SkillPermissionRegistry {
    let mut registry = SkillPermissionRegistry::default();

    for skill in mentioned_skills {
        let Some(permissions) = skill.permissions.clone() else {
            continue;
        };
        let Some(skill_dir) = skill.path.parent() else {
            continue;
        };

        let scripts_dir = skill_dir.join("scripts");
        if !scripts_dir.is_dir() {
            continue;
        }

        let profile_id = format!("{}:{}", skill.path.display(), skill.name);
        let profile = Arc::new(SkillPermissionProfile {
            id: profile_id.clone(),
            skill_name: skill.name.clone(),
            skill_path: skill.path.clone(),
            permissions,
        });
        registry.profiles.insert(profile_id.clone(), profile);

        for script_path in discover_script_files(&scripts_dir) {
            let canonical_script = canonicalize_path(&script_path).unwrap_or(script_path);
            registry
                .script_to_profile_id
                .insert(canonical_script.clone(), profile_id.clone());

            let canonical_script_str = canonical_script.to_string_lossy().to_string();
            registry.rules.push(SkillPermissionRule {
                pattern: vec![canonical_script_str.clone()],
                profile_id: profile_id.clone(),
                script_path: canonical_script.clone(),
            });
            for interpreter in KNOWN_SCRIPT_INTERPRETERS {
                registry.rules.push(SkillPermissionRule {
                    pattern: vec![interpreter.to_string(), canonical_script_str.clone()],
                    profile_id: profile_id.clone(),
                    script_path: canonical_script.clone(),
                });
            }
        }
    }

    registry
}

impl SkillPermissionRegistry {
    pub(crate) fn match_command(
        &self,
        command: &[String],
        cwd: &Path,
        base_sandbox_policy: &SandboxPolicy,
    ) -> Option<SkillPermissionContext> {
        let script_path = commands_for_matching(command)
            .into_iter()
            .find_map(|candidate| resolve_invoked_script_path(&candidate, cwd, self));
        let script_path = script_path?;
        let profile_id = self.script_to_profile_id.get(&script_path)?;
        let profile = self.profiles.get(profile_id)?;
        let reason = build_permission_reason(profile);
        let sandbox_policy_override =
            derive_sandbox_policy(base_sandbox_policy, &profile.permissions, cwd);

        Some(SkillPermissionContext {
            profile_id: profile.id.clone(),
            reason,
            sandbox_policy_override,
        })
    }
}

fn commands_for_matching(command: &[String]) -> Vec<Vec<String>> {
    if let Some(commands) = parse_shell_lc_plain_commands(command)
        && !commands.is_empty()
    {
        return commands;
    }

    if let Some(single_command) = parse_shell_lc_single_command_prefix(command) {
        return vec![single_command];
    }

    vec![command.to_vec()]
}

fn resolve_invoked_script_path(
    command: &[String],
    cwd: &Path,
    registry: &SkillPermissionRegistry,
) -> Option<PathBuf> {
    let first = command.first()?;
    if let Some(path) = resolve_script_path_token(first, cwd, registry) {
        return Some(path);
    }

    if command.len() < 2 || !KNOWN_SCRIPT_INTERPRETERS.contains(&first.as_str()) {
        return None;
    }
    resolve_script_path_token(&command[1], cwd, registry)
}

fn resolve_script_path_token(
    token: &str,
    cwd: &Path,
    registry: &SkillPermissionRegistry,
) -> Option<PathBuf> {
    let path = PathBuf::from(token);
    if !path.is_absolute() && !token.starts_with("./") && !token.starts_with("../") {
        return None;
    }

    let absolute = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    let canonical = canonicalize_path(&absolute).unwrap_or(absolute);
    registry
        .script_to_profile_id
        .contains_key(&canonical)
        .then_some(canonical)
}

fn derive_sandbox_policy(
    base_sandbox_policy: &SandboxPolicy,
    permissions: &SkillPermissions,
    cwd: &Path,
) -> SandboxPolicy {
    match base_sandbox_policy {
        SandboxPolicy::DangerFullAccess | SandboxPolicy::ExternalSandbox { .. } => {
            base_sandbox_policy.clone()
        }
        SandboxPolicy::ReadOnly => workspace_write_extension_from_permissions(
            Vec::new(),
            false,
            false,
            false,
            permissions,
            cwd,
        ),
        SandboxPolicy::WorkspaceWrite {
            writable_roots,
            network_access,
            exclude_tmpdir_env_var,
            exclude_slash_tmp,
        } => workspace_write_extension_from_permissions(
            writable_roots.clone(),
            *network_access,
            *exclude_tmpdir_env_var,
            *exclude_slash_tmp,
            permissions,
            cwd,
        ),
    }
}

fn workspace_write_extension_from_permissions(
    mut writable_roots: Vec<AbsolutePathBuf>,
    mut network_access: bool,
    exclude_tmpdir_env_var: bool,
    exclude_slash_tmp: bool,
    permissions: &SkillPermissions,
    cwd: &Path,
) -> SandboxPolicy {
    if permissions.network.unwrap_or(false) {
        network_access = true;
    }

    if let Some(fs_write) = permissions.fs_write.as_ref() {
        for path in fs_write {
            match path.to_str() {
                Some(":project_roots") => {
                    if let Ok(path) = AbsolutePathBuf::from_absolute_path(cwd) {
                        writable_roots.push(path);
                    }
                }
                Some(":tmp") | Some(":minimal") => {}
                _ => {
                    if let Ok(path) = AbsolutePathBuf::from_absolute_path(path) {
                        writable_roots.push(path);
                    }
                }
            }
        }
    }

    writable_roots.sort_unstable_by(|a, b| a.as_path().cmp(b.as_path()));
    writable_roots.dedup();

    SandboxPolicy::WorkspaceWrite {
        writable_roots,
        network_access,
        exclude_tmpdir_env_var,
        exclude_slash_tmp,
    }
}

fn build_permission_reason(profile: &SkillPermissionProfile) -> String {
    let mut capabilities = Vec::new();
    let permissions = &profile.permissions;
    if permissions.network.unwrap_or(false) {
        capabilities.push("network access");
    }
    if permissions
        .fs_write
        .as_ref()
        .is_some_and(|paths| !paths.is_empty())
    {
        capabilities.push("filesystem write access");
    }
    if permissions
        .fs_read
        .as_ref()
        .is_some_and(|paths| !paths.is_empty())
    {
        capabilities.push("additional filesystem read access");
    }
    if permissions.macos_launch_services.unwrap_or(false) {
        capabilities.push("macOS launch services");
    }
    if permissions.macos_preferences.unwrap_or(false) {
        capabilities.push("macOS preferences");
    }
    if permissions
        .macos_automation
        .as_ref()
        .is_some_and(|targets| !targets.is_empty())
    {
        capabilities.push("macOS automation");
    }
    if permissions.macos_accessibility.unwrap_or(false) {
        capabilities.push("macOS accessibility");
    }
    if permissions.macos_calendar.unwrap_or(false) {
        capabilities.push("macOS calendar");
    }

    if capabilities.is_empty() {
        format!(
            "skill `{}` requires elevated permissions",
            profile.skill_name
        )
    } else {
        format!(
            "skill `{}` requires {}",
            profile.skill_name,
            capabilities.join(", ")
        )
    }
}

fn discover_script_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut scripts = Vec::new();

    while let Some(dir) = pending.pop() {
        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                scripts.push(path);
            }
        }
    }

    scripts
}
