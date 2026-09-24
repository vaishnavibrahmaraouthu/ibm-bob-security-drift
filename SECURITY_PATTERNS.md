# Security Patterns

This repository follows these security patterns for authentication.

## Password Security

- User passwords must be hashed using bcrypt.
- Passwords must never be stored in plaintext.
- Password verification must use bcrypt comparison.

## Authentication

- Authentication uses JWT.
- JWT signing uses the `JWT_SECRET` environment variable.
- JWTs should have a defined expiration time.

## Error Handling

- Authentication failures should use generic error messages.
- Login should not reveal whether an email/account exists.
- Unexpected server errors should return a generic `Server error` response.

## Sensitive Data

- Passwords should never be returned in API responses.
- Sensitive tokens should be handled securely.
- Security-sensitive values should not be exposed unnecessarily.

## Security-Sensitive Randomness

- Security-sensitive tokens must use a cryptographically secure random generator.
- `Math.random()` must not be used for authentication or password-reset tokens.

## Password Reset

Password-reset functionality should follow the same security principles as the existing authentication system:

- Reset tokens must be unpredictable.
- Reset tokens must expire.
- Reset tokens should not be unnecessarily exposed.
- Password reset responses should avoid revealing whether an account exists.
- New passwords must be hashed with bcrypt.
- Reset tokens must be invalidated after successful use.