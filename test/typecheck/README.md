# OpenIM Typecheck

OpenIM Typecheck 为所有 Go 构建平台进行跨平台源代码类型检查。

## 优点

- **速度**：OpenIM 完整编译大约需要 3 分钟，而使用 Typecheck 只需数秒。
- **资源消耗**：与需要 >40GB 的 RAM 不同，Typecheck 只需 <8GB 的 RAM。

## 实现

OpenIM Typecheck 使用 Go 内置的解析和类型检查库 (`go/parser` 和 `go/types`)。然而，这些库并不是 go 编译器所使用的。偶尔会出现不匹配的情况，但总的来说，它们是相当接近的。

## 错误处理

如果错误不会阻止构建，可以忽略。

**`go/types` 报告的错误，但 `go build` 不会**：
- **真正的错误**（根据规范）：
  - 应尽量修复。如果无法修复或正在进行中（例如，已被外部引用的代码），则可以忽略。
    - 例如：闭包中的未使用变量
- **不真实的错误**：
  - 应忽略并在适当的情况下向上游报告。
    - 例如：staging 和 generated 类型之间的类型检查不匹配

**`go build` 报告的错误，但我们不会**：
- CGo 错误，包括语法和链接器错误。