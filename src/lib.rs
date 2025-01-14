/*!
Provides basic traits and helper structures for user authentication.
*/

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Trait for user authentication.
///
/// This trait defines the necessary methods for user identification and authentication.
/// Implementations should ensure that each user can be uniquely identified and authenticated.
#[typetag::serde]
pub trait UserTrait: Debug + Send + Sync {
    /// Returns a unique string identifier for the user.
    /// This is equivalent to a username and is used in non-sensitive environments.
    fn identity_str(&self) -> &str;

    /// Returns a byte slice of the unique identifier for the user.
    /// This can be the same as `identity_str` or different, depending on implementation.
    fn identity_bytes(&self) -> &[u8];

    /// Returns a string used for authenticating the user.
    /// This is equivalent to a combination of username and password.
    /// Implementations should prefix the string with a type identifier, e.g., "plaintext:u0 p0".
    fn auth_str(&self) -> &str;

    /// Returns a byte slice used for authenticating the user.
    /// This can be the same as `auth_str` or different, depending on implementation.
    fn auth_bytes(&self) -> &[u8];
}

/// A cloneable [`UserTrait`].
///
/// Note: Using `DynClone` allows for cloning of trait objects, which is not possible with `Clone` alone.
pub trait User: UserTrait + DynClone {}

/// Implements User trait for any type that implements UserTrait and DynClone
impl<T: UserTrait + DynClone> User for T {}

// Enables cloning of User trait objects
dyn_clone::clone_trait_object!(User);

/// A wrapper for a boxed user implementing the `User` trait.
///
/// This struct provides implementations for `Debug`, `Hash`, `PartialOrd`, `Ord`, `PartialEq`, and `Eq`.
#[derive(Clone)]
pub struct UserBox(pub Box<dyn User>);

impl Debug for UserBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UserBox").field(&self.0.auth_str()).finish()
    }
}

impl Hash for UserBox {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.auth_str().hash(state);
    }
}

impl PartialOrd for UserBox {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserBox {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.auth_str().cmp(&other.0.auth_str())
    }
}

impl PartialEq for UserBox {
    fn eq(&self, other: &Self) -> bool {
        self.0.auth_str() == other.0.auth_str()
    }
}

impl Eq for UserBox {}

/// A Vec of `UserBox` with additional functionality.
///
/// This struct provides a method to  hash the set, NOT ensuring consistent hash values
/// regardless of the order of elements.
///
/// This is intended. As different orders are considered to be important in the UserVec's case.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserVec(pub Vec<UserBox>);

impl Hash for UserVec {
    /// hashes its contents with the order of the vec.
    ///
    /// This ensures that the hash value is not the same for different orders of different users.
    ///
    /// The hash is different if the content is the same but with an different order.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.iter().for_each(|b| {
            b.hash(state);
        })
    }
}

/// Trait for asynchronous user authentication.
///
/// This trait defines a method for authenticating users based on an authentication string.
pub trait UserAuthenticator<T: User> {
    /// Authenticates a user using the provided authentication string.
    fn auth_user_by_authstr(&self, authstr: &str) -> Option<T>;
}

/// A simple implementation of a user with plaintext username and password.
///
/// This struct provides methods for creating and validating plaintext users.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PlainText {
    pub user: String,

    /// The field is intended to be stored in plaintext.
    /// If the user wants more security, they should have a custom struct
    /// that implements the [`UserTrait`] trait.
    pub pass: String,

    auth_str: String,
}

impl From<&str> for PlainText {
    /// Creates a new `PlainText` user from a single string containing both username and password.
    ///
    /// The string is split by whitespace to separate the username and password.
    ///
    /// For example, "user1 pass1" will create a user with username "user1" and password "pass1".
    ///
    /// If the string does not contain a password, the password will be an empty string.
    ///
    /// If the string does not contain a username, the username will be the entire string.
    ///
    /// If the string is empty, the user will be created with an empty username and password.
    fn from(userpass: &str) -> Self {
        let (user, pass) = userpass
            .split_once(char::is_whitespace)
            .unwrap_or((userpass, ""));
        PlainText::new(user.to_string(), pass.to_string())
    }
}

impl PlainText {
    /// Creates a new `PlainText` user with the specified username and password.
    ///
    /// The authentication string is formatted as "plaintext:{user}\n{pass}".
    pub fn new(user: String, pass: String) -> Self {
        let astr = format!("plaintext:{}\n{}", user, pass);
        PlainText {
            user,
            pass,
            auth_str: astr,
        }
    }

    /// Checks if the user is valid by ensuring the username is not empty.
    pub fn valid(&self) -> bool {
        !self.user.is_empty()
    }

    /// Checks if both username and password are not empty.
    pub fn password_non_empty(&self) -> bool {
        !self.user.is_empty() && !self.pass.is_empty()
    }

    /// Returns the authentication string for the user.
    pub fn auth_str(&self) -> &str {
        self.auth_str.as_str()
    }
}

#[typetag::serde]
impl UserTrait for PlainText {
    fn identity_str(&self) -> &str {
        self.user.as_str()
    }

    fn identity_bytes(&self) -> &[u8] {
        self.user.as_bytes()
    }

    fn auth_str(&self) -> &str {
        self.auth_str.as_str()
    }

    fn auth_bytes(&self) -> &[u8] {
        self.auth_str.as_bytes()
    }
}

/// A map structure that stores users with both identity and authentication mappings.
///
/// Contains two internal hashmaps:
/// - id_map: Maps user identities to user instances
/// - auth_map: Maps authentication strings to user instances
#[derive(Debug, Clone, Default)]
pub struct UsersMap<T: UserTrait + Clone> {
    /// Maps user identity strings to user instances
    id_map: HashMap<String, Arc<T>>,

    /// Maps user authentication strings to user instances
    /// Note that the keys for auth_map are different from keys for id_map.
    auth_map: HashMap<String, Arc<T>>,
}

impl<T: UserTrait + Clone> UsersMap<T> {
    /// Adds a new user to both id_map and auth_map
    pub fn add_user(&mut self, user: T) {
        let user = Arc::new(user);

        self.id_map
            .insert(user.identity_str().to_string(), Arc::clone(&user));
        self.auth_map
            .insert(user.auth_str().to_string(), Arc::clone(&user));
    }

    /// Removes a user from both maps using their identity string
    pub fn remove_user(&mut self, id: &str) {
        if let Some(user) = self.id_map.remove(id) {
            self.auth_map.remove(&user.auth_str().to_string());
        }
    }

    /// Retrieves a user by their identity string
    pub fn get_user(&self, id: &str) -> Option<Arc<T>> {
        self.id_map.get(id).map(Arc::clone)
    }

    /// Retrieves a user by their authentication string
    pub fn get_user_by_authstr(&self, authstr: &str) -> Option<Arc<T>> {
        self.auth_map.get(authstr).map(Arc::clone)
    }
}

/// Implementation of UserAuthenticator trait for UsersMap
impl<T: UserTrait + Clone> UserAuthenticator<T> for UsersMap<T> {
    /// Authenticates a user by their authentication string and returns a clone if found
    fn auth_user_by_authstr(&self, authstr: &str) -> Option<T> {
        self.auth_map
            .get(authstr)
            .map(|arc_user| Arc::clone(arc_user).as_ref().clone())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::PlainText;
    use crate::{UserAuthenticator, UsersMap};

    #[test]
    fn test_hashmap() {
        let mut map = HashMap::new();
        map.insert(1, "a");
        assert_eq!(map.get(&1), Some(&"a"));
        assert_eq!(map.get(&2), None);

        let mut map = HashMap::new();
        let k = 1.to_string();
        map.insert(k.as_str(), "a");
        assert_eq!(map.get("1"), Some(&"a"));
    }

    #[test]
    fn test_users_map() -> Result<(), Box<dyn std::error::Error>> {
        let up = PlainText::new("u".into(), "p".into());
        let up2 = PlainText::new("u2".into(), "p2".into());

        let mut um: UsersMap<PlainText> = UsersMap::default();
        um.add_user(up);
        um.add_user(up2);

        let o = um.auth_user_by_authstr("plaintext:u");

        if o.is_some() {
            panic!("o.is_some() ");
        }

        let o = um.auth_user_by_authstr("plaintext:u2\np2");

        if o.is_none() {
            panic!("o.is_none()")
        } else {
            Ok(())
        }
    }
}
