use crate::Error;
use chrono::{DateTime, Utc};
use grin_util::ToHex;
use grin_wallet_libwallet::Slate;
use rand::RngCore;
use ring::digest::{digest, SHA256};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiSigConfig {
	pub threshold: u8,
	pub participants: Vec<MultiSigParticipant>,
	pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiSigParticipant {
	pub id: String,
	pub storage_file: String,
	pub token_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantStorage {
	pub id: String,
	pub token: String,
	pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
	Pending,
	Finalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionApproval {
	pub participant_id: String,
	pub approved_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiSigSession {
	pub slate_id: String,
	pub amount: u64,
	pub required_approvals: u8,
	pub participants: Vec<String>,
	pub created_at: DateTime<Utc>,
	pub status: SessionStatus,
	pub approvals: Vec<SessionApproval>,
	pub finalized_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct ParticipantInitResult {
	pub id: String,
	pub storage_path: PathBuf,
}

struct MultiSigPaths {
	_root: PathBuf,
	config: PathBuf,
	participants: PathBuf,
	sessions: PathBuf,
}

impl MultiSigPaths {
	fn new(base: &Path) -> Self {
		let root = base.join("multisig");
		let participants = root.join("participants");
		let sessions = root.join("sessions");
		let config = root.join("config.json");
		MultiSigPaths {
			_root: root,
			config,
			participants,
			sessions,
		}
	}

	fn ensure_dirs(&self) -> Result<(), Error> {
		fs::create_dir_all(&self.participants).map_err(|e| {
			Error::GenericError(format!("Unable to create participants directory: {}", e))
		})?;
		fs::create_dir_all(&self.sessions).map_err(|e| {
			Error::GenericError(format!("Unable to create sessions directory: {}", e))
		})?;
		Ok(())
	}
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
	let data = serde_json::to_vec_pretty(value).map_err(|e| {
		Error::GenericError(format!(
			"Unable to serialize data to {}: {}",
			path.display(),
			e
		))
	})?;
	let mut file = File::create(path)
		.map_err(|e| Error::GenericError(format!("Unable to create {}: {}", path.display(), e)))?;
	file.write_all(&data)
		.map_err(|e| Error::GenericError(format!("Unable to write {}: {}", path.display(), e)))?;
	file.sync_all()
		.map_err(|e| Error::GenericError(format!("Unable to sync {}: {}", path.display(), e)))?;
	Ok(())
}

fn read_json_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, Error> {
	if !path.exists() {
		return Ok(None);
	}
	let mut file = File::open(path)
		.map_err(|e| Error::GenericError(format!("Unable to open {}: {}", path.display(), e)))?;
	let mut data = String::new();
	file.read_to_string(&mut data)
		.map_err(|e| Error::GenericError(format!("Unable to read {}: {}", path.display(), e)))?;
	let value = serde_json::from_str(&data)
		.map_err(|e| Error::GenericError(format!("Unable to parse {}: {}", path.display(), e)))?;
	Ok(Some(value))
}

fn hash_token(token: &str) -> String {
	let digest = digest(&SHA256, token.as_bytes());
	digest.as_ref().to_hex()
}

fn generate_token() -> String {
	let mut bytes = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut bytes);
	bytes.to_hex()
}

fn participant_file_path(paths: &MultiSigPaths, participant_id: &str) -> PathBuf {
	paths.participants.join(format!("{}.json", participant_id))
}

fn session_file_path(paths: &MultiSigPaths, slate_id: &str) -> PathBuf {
	paths.sessions.join(format!("{}.json", slate_id))
}

fn load_session(paths: &MultiSigPaths, slate_id: &str) -> Result<Option<MultiSigSession>, Error> {
	read_json_optional::<MultiSigSession>(&session_file_path(paths, slate_id))
}

fn save_session(paths: &MultiSigPaths, session: &MultiSigSession) -> Result<(), Error> {
	let file_path = session_file_path(paths, &session.slate_id);
	write_json(&file_path, session)
}

fn load_config(paths: &MultiSigPaths) -> Result<Option<MultiSigConfig>, Error> {
	read_json_optional::<MultiSigConfig>(&paths.config)
}

pub fn status(base: &Path) -> Result<Option<MultiSigConfig>, Error> {
	let paths = MultiSigPaths::new(base);
	load_config(&paths)
}

pub fn is_configured(base: &Path) -> Result<bool, Error> {
	let paths = MultiSigPaths::new(base);
	Ok(paths.config.exists())
}

pub fn initialize(
	base: &Path,
	threshold: u8,
	participants: Vec<String>,
) -> Result<Vec<ParticipantInitResult>, Error> {
	if threshold == 0 {
		return Err(Error::Multisig(
			"Threshold must be greater than zero".to_string(),
		));
	}
	if participants.is_empty() {
		return Err(Error::Multisig(
			"At least one participant must be provided".to_string(),
		));
	}
	if threshold as usize > participants.len() {
		return Err(Error::Multisig(format!(
			"Threshold {} exceeds number of participants {}",
			threshold,
			participants.len()
		)));
	}

	let paths = MultiSigPaths::new(base);
	if paths.config.exists() {
		return Err(Error::Multisig(
			"A multi-signature configuration already exists. Use 'status' to review it."
				.to_string(),
		));
	}
	paths.ensure_dirs()?;

	let now = Utc::now();
	let mut stored_participants = Vec::new();
	let mut results = Vec::new();

	for id in participants {
		if stored_participants
			.iter()
			.any(|p: &MultiSigParticipant| p.id == id)
		{
			return Err(Error::Multisig(format!(
				"Duplicate participant identifier '{}' provided",
				id
			)));
		}
		let token = generate_token();
		let storage = ParticipantStorage {
			id: id.clone(),
			token: token.clone(),
			created_at: now,
		};
		let storage_path = participant_file_path(&paths, &id);
		write_json(&storage_path, &storage)?;
		stored_participants.push(MultiSigParticipant {
			id: id.clone(),
			storage_file: format!("participants/{}.json", &id),
			token_hash: hash_token(&token),
		});
		results.push(ParticipantInitResult { id, storage_path });
	}

	let config = MultiSigConfig {
		threshold,
		participants: stored_participants,
		created_at: now,
	};
	write_json(&paths.config, &config)?;
	Ok(results)
}

pub fn create_pending_session(base: &Path, slate: &Slate) -> Result<(), Error> {
	let paths = MultiSigPaths::new(base);
	let Some(config) = load_config(&paths)? else {
		return Ok(());
	};
	paths.ensure_dirs()?;
	let session_id = slate.id.to_string();
	let mut session = match load_session(&paths, &session_id)? {
		Some(existing) => existing,
		None => MultiSigSession {
			slate_id: session_id.clone(),
			amount: slate.amount,
			required_approvals: config.threshold,
			participants: config.participants.iter().map(|p| p.id.clone()).collect(),
			created_at: Utc::now(),
			status: SessionStatus::Pending,
			approvals: vec![],
			finalized_at: None,
		},
	};
	if session.status == SessionStatus::Finalized {
		return Ok(());
	}
	if session.amount != slate.amount {
		session.amount = slate.amount;
	}
	save_session(&paths, &session)
}

pub fn ensure_threshold(base: &Path, slate: &Slate) -> Result<(), Error> {
	let paths = MultiSigPaths::new(base);
	let Some(config) = load_config(&paths)? else {
		return Ok(());
	};
	let session_id = slate.id.to_string();
	let mut session = match load_session(&paths, &session_id)? {
		Some(s) => s,
		None => {
			create_pending_session(base, slate)?;
			load_session(&paths, &session_id)?.unwrap()
		}
	};
	if session.status == SessionStatus::Finalized {
		return Ok(());
	}
	if session.amount != slate.amount {
		session.amount = slate.amount;
		save_session(&paths, &session)?;
	}
	let approval_set: HashSet<_> = session
		.approvals
		.iter()
		.map(|a| a.participant_id.as_str())
		.collect();
	let approved = approval_set.len() as u8;
	if approved < session.required_approvals {
		let missing: Vec<_> = config
			.participants
			.iter()
			.filter(|p| !approval_set.contains(p.id.as_str()))
			.map(|p| p.id.clone())
			.collect();
		return Err(Error::Multisig(format!(
			"Slate {} requires {} approvals ({} recorded). Pending holders: {}",
			&session_id,
			session.required_approvals,
			approved,
			if missing.is_empty() {
				String::from("none")
			} else {
				missing.join(", ")
			}
		)));
	}
	Ok(())
}

pub fn mark_finalized(base: &Path, slate: &Slate) -> Result<(), Error> {
	let paths = MultiSigPaths::new(base);
	let Some(_) = load_config(&paths)? else {
		return Ok(());
	};
	let session_id = slate.id.to_string();
	let mut session = match load_session(&paths, &session_id)? {
		Some(s) => s,
		None => return Ok(()),
	};
	if session.status != SessionStatus::Finalized {
		session.status = SessionStatus::Finalized;
		session.finalized_at = Some(Utc::now());
		session.amount = slate.amount;
		save_session(&paths, &session)?;
	}
	Ok(())
}

pub fn approve(
	base: &Path,
	session_id: &str,
	participant_id: &str,
	token: &str,
) -> Result<MultiSigSession, Error> {
	let paths = MultiSigPaths::new(base);
	let Some(config) = load_config(&paths)? else {
		return Err(Error::Multisig(
			"Multi-signature has not been initialized".to_string(),
		));
	};
	let participant = config
		.participants
		.iter()
		.find(|p| p.id == participant_id)
		.ok_or_else(|| Error::Multisig(format!("Unknown participant '{}'", participant_id)))?;

	let token_hash = hash_token(token);
	if token_hash != participant.token_hash {
		return Err(Error::Multisig(
			"Approval token does not match configured holder".to_string(),
		));
	}

	let mut session = match load_session(&paths, session_id)? {
		Some(s) => s,
		None => {
			return Err(Error::Multisig(format!(
				"No pending session found for slate {}",
				session_id
			)));
		}
	};

	if session.status == SessionStatus::Finalized {
		return Err(Error::Multisig(
			"This session has already been finalized".to_string(),
		));
	}

	if session
		.approvals
		.iter()
		.any(|a| a.participant_id == participant_id)
	{
		return Ok(session);
	}

	session.approvals.push(SessionApproval {
		participant_id: participant_id.to_owned(),
		approved_at: Utc::now(),
	});
	save_session(&paths, &session)?;
	Ok(session)
}

pub fn list_sessions(base: &Path, include_finalized: bool) -> Result<Vec<MultiSigSession>, Error> {
	let paths = MultiSigPaths::new(base);
	let Some(_) = load_config(&paths)? else {
		return Ok(vec![]);
	};
	if !paths.sessions.exists() {
		return Ok(vec![]);
	}
	let mut sessions = Vec::new();
	for entry in fs::read_dir(&paths.sessions)
		.map_err(|e| Error::GenericError(format!("Unable to read sessions directory: {}", e)))?
	{
		let entry = entry
			.map_err(|e| Error::GenericError(format!("Unable to read session entry: {}", e)))?;
		let path = entry.path();
		if path.extension().and_then(|s| s.to_str()) != Some("json") {
			continue;
		}
		if let Some(session) = read_json_optional::<MultiSigSession>(&path)? {
			if include_finalized || session.status == SessionStatus::Pending {
				sessions.push(session);
			}
		}
	}
	sessions.sort_by(|a, b| a.created_at.cmp(&b.created_at));
	Ok(sessions)
}

pub fn participant_storage_path(base: &Path, participant_id: &str) -> PathBuf {
	let paths = MultiSigPaths::new(base);
	participant_file_path(&paths, participant_id)
}

pub fn load_participant_storage(
	base: &Path,
	participant_id: &str,
) -> Result<Option<ParticipantStorage>, Error> {
	let paths = MultiSigPaths::new(base);
	read_json_optional::<ParticipantStorage>(&participant_file_path(&paths, participant_id))
}
