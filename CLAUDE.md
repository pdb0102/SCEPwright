# Repo conventions

This repo is the **SCEP testing suite** (IntuneSimulator + ScepTestClient).

## ScepTestClient code style (src/ScepTestClient.*, tests/ScepTestClient.Tests)
- **Never `var`** — always the explicit type (enforced by `.editorconfig`).
- **Declare locals at the top of the block, unassigned, then a blank line, then assignments.** Example:

  ```csharp
  int count;
  string name;

  count = items.Length;
  name = items[0].Name;
  ```
- No exceptions for control flow: static `Create()`/`Load()` factories; sync returns a result enum + `out value` + `out string error`; async returns `ScepResult<T>`.
- All cryptography goes through `IScepCrypto`; never reference a crypto library outside `ScepTestClient.Crypto.*`.

The existing IntuneSimulator projects keep their modern idioms (`var`, LINQ); these rules apply to ScepTestClient code only.
