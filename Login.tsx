import React from "react";

type LoginProps = {
  bio: string;
  redirectUrl: string;
  expression: string;
};

export default function Login({
  bio,
  redirectUrl,
  expression,
}: LoginProps) {
  // ISSUE 1: Hardcoded credential
  const adminPassword = "admin123";

  // ISSUE 2: Sensitive token stored in localStorage
  const saveToken = (token: string) => {
    localStorage.setItem("auth_token", token);
  };

  // ISSUE 3: Arbitrary JavaScript execution
  const runExpression = () => {
    eval(expression);
  };

  // ISSUE 4: Unvalidated redirect
  const redirectUser = () => {
    window.location.href = redirectUrl;
  };

  return (
    <div>
      <h1>Login</h1>

      {/* ISSUE 5: User-controlled HTML rendered directly */}
      <div
        dangerouslySetInnerHTML={{
          __html: bio,
        }}
      />

      <button
        onClick={() =>
          saveToken("demo-sensitive-token")
        }
      >
        Login
      </button>

      <button onClick={runExpression}>
        Run
      </button>

      <button onClick={redirectUser}>
        Continue
      </button>

      <p>{adminPassword}</p>
    </div>
  );
}
