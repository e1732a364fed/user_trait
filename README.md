# User-Trait

This library provides basic traits and helper structures for user authentication in Rust. It includes functionality for user identification, authentication, and storage, aiming to provide a simple enough interface for user authentication.

## Features

- **UserTrait**: A trait defining methods for user identification and authentication.
- **UserBox**: A wrapper for a boxed user implementing the `User` trait, with support for hashing and ordering.
- **UserVec**: A vector of `UserBox` with additional functionality for sorting and hashing.
- **UserAuthenticator**: A trait for user authentication.
- **PlainText**: A simple implementation of a user with plaintext username and password.
- **UsersMap**: A map for storing users, implementing `UserAuthenticator`.

## Usage

To use this library, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
user_trait = "0.1.0"
```

```rust
use user_trait::{PlainText, UsersMap, AsyncUserAuthenticator};

fn main() {
    let user1 = PlainText::new("user1".to_string(), "password1".to_string());
    let user2 = PlainText::new("user2".to_string(), "password2".to_string());
    let mut users_map = UsersMap::new();
    users_map.add_user(user1);
    users_map.add_user(user2);

    if let Some(authenticated_user) = users_map.auth_user_by_authstr("plaintext:user2\npassword2") {

        println!("User authenticated: {}", authenticated_user.identity_str());
    } else {
        println!("Authentication failed.");
    }
}

```

## Similar Projects

[password-hash](https://crates.io/crates/password-hash)

## License

This project is licensed under the MIT OR Apache-2.0 License.
