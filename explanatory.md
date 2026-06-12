# Beginner Explanatory Guide: PLATFORM-2850: Fix JWT Token Expiry Bypass Vulnerability

> **Task Type**: Product Task  
> **Domain/Focus**: Authentication Middleware, Security

---

## 1. The Goal (In-Depth Beginner Explanation)

### The Core Problem
The task at hand addresses a critical security vulnerability in the authentication middleware of our application. Currently, the middleware accepts JSON Web Tokens (JWTs) that have expired, which poses a significant risk to the system. Expired tokens should not grant access to users, as they may allow unauthorized individuals to exploit the system. This vulnerability was highlighted during a security audit, which revealed that expired tokens were still being accepted, leading to potential unauthorized access to sensitive data and functionalities.

Moreover, the middleware does not check for revoked tokens, meaning that if a user changes their password or logs out, their previous token remains valid. This can lead to scenarios where a malicious actor could use a revoked token to gain access to the system, further compromising user security. Fixing these issues is paramount to ensuring the integrity of user sessions and protecting sensitive information from unauthorized access.

### Jargon Buster (Key Terms Explained)
* **JWT (JSON Web Token)**: A compact, URL-safe means of representing claims to be transferred between two parties. For example, a JWT can be used to verify the identity of a user and to ensure that the user has the necessary permissions to access certain resources. It consists of three parts: a header, a payload, and a signature.

* **Token Expiry**: This refers to the time limit set on a token, after which it is no longer valid. For instance, if a token has an expiry time set to one hour, it will be rejected by the server if presented after that hour has passed. This is crucial for maintaining security, as it limits the time frame in which a token can be misused.

* **Token Revocation**: This is the process of invalidating a token before its expiry time. For example, if a user logs out or changes their password, the system should revoke their existing tokens to prevent unauthorized access. This is typically managed through a blacklist of revoked tokens.

* **Algorithm (in JWT context)**: This refers to the method used to sign the JWT. For example, 'HS256' is a widely used algorithm that employs HMAC with SHA-256. If a token is signed with an algorithm that is not secure (like 'none'), it can be easily forged, leading to security vulnerabilities.

### Expected Outcome
After implementing the necessary fixes, the authentication middleware should behave as follows:
- **Before**: Expired tokens are accepted, allowing unauthorized access. Revoked tokens remain valid, and the algorithm used for signing tokens is insecure ('none').
- **After**: Expired tokens will return a 401 Unauthorized response with the message "Token expired." Revoked tokens will also return a 401 Unauthorized response with the message "Token revoked." Additionally, the middleware will enforce the use of the 'HS256' algorithm, rejecting any tokens signed with insecure algorithms.

---

## 2. Related Coding Concepts & Syntax (50% Theory, 50% Practice)

### Concept 1: Token Validation
#### 📘 Theoretical Overview (50%)
Token validation is a crucial process in authentication systems that ensures only legitimate tokens are accepted. This involves checking various claims within the token, such as the expiry time (`exp`), which indicates when the token should no longer be considered valid. If the current time exceeds this expiry time, the token should be rejected.

Additionally, validating tokens involves checking against a blacklist of revoked tokens. This ensures that even if a token is still technically valid (not expired), it cannot be used if the user has logged out or changed their password. Without proper validation, the system remains vulnerable to unauthorized access, which can lead to data breaches and loss of user trust.

#### 💻 Syntax & Practical Examples (50%)
* **Language Syntax**:
  ```typescript
  function validateToken(token: string): boolean {
      const payload = decodeToken(token);
      const currentTime = Date.now() / 1000; // Convert to seconds
      if (payload.exp < currentTime) {
          return false; // Token is expired
      }
      if (revokedTokens.has(token)) {
          return false; // Token is revoked
      }
      return true; // Token is valid
  }
  ```

* **Real-World Application**:
  ```typescript
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
  const isValid = validateToken(token);
  if (!isValid) {
      throw new Error("Unauthorized access: Token is invalid or expired.");
  }
  ```

---

## 3. Step-by-Step Logic & Walkthrough

1. **Step 1: Locate and Analyze the Target File**
   * Navigate to the `p-w02-hotfix-01` folder and open the `authMiddleware.ts` file. This file contains the middleware logic for handling JWT authentication.
   * Focus on the section of the code where the token is being verified. Look for comments marked with `BUG` to identify the areas that need fixing.

2. **Step 2: Input Verification & Validation**
   * Check if the token is present and valid. If the token is null or undefined, return a 401 Unauthorized response immediately. This prevents any further processing of invalid tokens.

3. **Step 3: Core Implementation / Modification**
   * Implement the expiry check by comparing the `exp` claim in the token payload against the current time. If the token is expired, return a 401 response with the message "Token expired."
   * Add a check against the `revokedTokens` set to see if the token has been revoked. If it has, return a 401 response with the message "Token revoked."
   * Ensure that the algorithm used for signing the token is 'HS256'. If it is not, reject the token.

4. **Step 4: Output Verification & Testing**
   * After making the changes, run the tests included at the bottom of the `authMiddleware.ts` file. Use the command `npx jest tests/ --verbose` to execute the tests and verify that all cases pass successfully.

---

## 4. Detailed Walkthrough of Test Cases

### Test Case 1: Standard / Success Case
* **Description**: This test checks the behavior of the middleware when a valid, non-expired, and non-revoked token is provided.
* **Inputs**:
  ```json
  {
      "token": "valid-token-example"
  }
  ```
* **Step-by-Step Execution Trace**:
  1. The middleware receives the token "valid-token-example."
  2. The function checks the token's expiry time and finds it valid.
  3. The function checks the revoked tokens and finds it not revoked.
  4. The middleware allows access and returns a success response.
* **Expected Output**: The user is granted access to the requested resource.

### Test Case 2: Edge Case / Validation Fail
* **Description**: This test checks the behavior of the middleware when an expired token is provided.
* **Inputs**:
  ```json
  {
      "token": "expired-token-example"
  }
  ```
* **Step-by-Step Execution Trace**:
  1. The middleware receives the token "expired-token-example."
  2. The function checks the token's expiry time and finds it has expired.
  3. The middleware halts further processing and returns a 401 Unauthorized response.
* **Expected Output**: The response contains a 401 status code and the message "Token expired."