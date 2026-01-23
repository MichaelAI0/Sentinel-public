# TypeScript Style Guide

> **Modern TypeScript Best Practices for Production Applications**
>
> Based on Matt Pocock's [Total TypeScript](https://www.totaltypescript.com/) patterns

This comprehensive guide outlines TypeScript coding conventions for building robust, maintainable applications. These patterns are framework-agnostic and apply to any TypeScript project.

---

## Table of Contents

1. [Core Principles](#core-principles)
2. [Type vs Interface](#1-type-vs-interface)
3. [Literal Types with `as const`](#2-as-const-for-literal-types)
4. [The `satisfies` Operator](#3-satisfies-operator)
5. [Function Type Declarations](#4-function-type-declarations)
6. [Utility Types & Helpers](#5-utility-types)
7. [TSConfig Settings](#6-tsconfig-settings)
8. [Runtime Validation (Zod)](#7-zod-schema-patterns)
9. [Error Handling Patterns](#8-result-pattern)
10. [Import Conventions](#9-import-conventions)
11. [Naming Conventions](#10-naming-conventions)
12. [Advanced Patterns](#11-advanced-patterns)
13. [Testing Patterns](#12-testing-patterns)
14. [Anti-Patterns to Avoid](#13-anti-patterns-to-avoid)
15. [Project Structure](#14-project-structure-recommendations)
16. [Editor Configuration](#15-editor-configuration)
17. [Performance Considerations](#16-performance-considerations)
18. [Additional Resources](#17-additional-resources)

---

## Core Principles

1. **Use `type` by default, not `interface`** - Avoid declaration merging bugs
2. **Prefer `as const` for literal inference** - Get exact types, not widened ones
3. **Use `satisfies` for validation without widening** - Validate while keeping literal types
4. **Declare return types for top-level functions** - Aid readability and tooling
5. **Avoid the `Function` type - be specific** - Use proper function signatures
6. **Enable strict TypeScript settings** - Catch bugs at compile time
7. **Prefer composition over inheritance** - Use type unions and intersections
8. **Make illegal states unrepresentable** - Use discriminated unions
9. **Favor immutability** - Use `readonly` and `as const`
10. **Type from runtime, not vice versa** - Infer types from Zod schemas, not duplicate

---

## 1. Type vs Interface

### Rule: Use `type` by default

```typescript
// ✅ DO: Use type for all type definitions
type UserConfig = {
  name: string;
  timeout: number;
  retries?: number;
};

// ❌ DON'T: Use interface unless you need extends
interface UserConfig {
  name: string;
  timeout: number;
  retries?: number;
}
```

### When to use `interface`

Only use `interface` when you need object inheritance with `extends`:

```typescript
// ✅ Interface is appropriate here - we need extends
interface BaseError {
  message: string;
  code: string;
}

interface NetworkError extends BaseError {
  statusCode: number;
  url: string;
}
```

### Why types over interfaces?

1. **No declaration merging** - Interfaces can be accidentally extended, causing bugs
2. **Implicit index signature** - Types work better with `Record<K, V>` patterns
3. **Consistency** - One syntax for all type definitions

```typescript
// Declaration merging - unexpected interface behavior
interface User {
  name: string;
}

interface User {
  age: number; // This MERGES with the above!
}

// Types don't merge - you get an error
type User = {
  name: string;
};

type User = {
  // Error: Duplicate identifier
  age: number;
};
```

---

## 2. `as const` for Literal Types

Use `as const` to infer literal types and create deeply readonly objects:

```typescript
// ✅ DO: Use as const for config objects
const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;
type Severity = (typeof SEVERITY_LEVELS)[number]; // 'critical' | 'high' | 'medium' | 'low'

// ✅ DO: Use as const for enum-like patterns
const ERROR_CODES = {
  NOT_FOUND: 404,
  UNAUTHORIZED: 401,
  INTERNAL: 500,
} as const;

type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES]; // 404 | 401 | 500

// ❌ DON'T: Let TypeScript widen types unnecessarily
const levels = ["critical", "high", "medium", "low"]; // string[]
```

### `as const` is not a lie

Unlike `as Type`, which can be used to lie to TypeScript, `as const` is completely type-safe. It simply tells TypeScript to infer the narrowest possible type.

---

## 3. `satisfies` Operator

Use `satisfies` when you want to:

1. Validate that a value matches a type
2. Keep the **exact** inferred type (not widen it)

```typescript
type Routes = Record<string, { handler: () => void }>;

// ✅ DO: Use satisfies for validation while keeping literal types
const routes = {
  "/": { handler: () => {} },
  "/users": { handler: () => {} },
  "/admin": { handler: () => {} },
} satisfies Routes;

// TypeScript knows exactly which routes exist
routes["/users"]; // ✅ OK
routes["/unknown"]; // ❌ Error - property doesn't exist

// ❌ DON'T: Use colon annotation if you need exact types
const routes: Routes = {
  "/": { handler: () => {} },
};
routes["/unknown"]; // ⚠️ No error - type is widened to Record<string, ...>
```

### When to use `satisfies` vs colon annotation

| Use Case                                 | Syntax      |
| ---------------------------------------- | ----------- |
| Need exact literal types                 | `satisfies` |
| Variable may be reassigned to wider type | `: Type`    |
| Complex config validation                | `satisfies` |
| Function parameters                      | `: Type`    |

---

## 4. Function Type Declarations

### Declare return types for top-level functions

```typescript
// ✅ DO: Declare return types for exported/top-level functions
export const analyzeFile = (path: string): Promise<AnalysisResult> => {
  // implementation
};

// ✅ DO: This helps AI assistants and future readers understand intent
export function calculateEntropy(data: Uint8Array): number {
  // implementation
}

// ❌ DON'T: Omit return types on public API functions
export const analyzeFile = async (path: string) => {
  // return type is inferred - less clear for consumers
};
```

### Exception: React/JSX components

```typescript
// ✅ OK: JSX return types are obvious
const Button = ({ label }: { label: string }) => {
  return <button>{label}</button>;
};
```

### Never use `Function` type

```typescript
// ❌ DON'T: Use Function - it's too loose
const processCallback = (fn: Function) => {
  fn(); // No type safety at all
};

// ✅ DO: Be specific about function signatures
const processCallback = (fn: () => void) => {
  fn();
};

// ✅ DO: Use generics for flexible but safe function types
const processCallback = <T>(fn: (item: T) => void, item: T) => {
  fn(item);
};

// ✅ DO: For truly any function, use this pattern
type AnyFunction = (...args: unknown[]) => unknown;
```

---

## 5. Utility Types

### The `Prettify` Helper

Use `Prettify` to make hover previews more readable:

```typescript
// Add to packages/shared/src/types/utils.ts
type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

// Before Prettify - ugly hover
type User = { id: string } & { name: string } & { email: string };
// Hover shows: { id: string } & { name: string } & { email: string }

// After Prettify - clean hover
type User = Prettify<{ id: string } & { name: string } & { email: string }>;
// Hover shows: { id: string; name: string; email: string }
```

### Common utility patterns

```typescript
// Extract array element type
type ArrayElement<T> = T extends readonly (infer U)[] ? U : never;

// Make specific keys optional
type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

// Make specific keys required
type RequiredBy<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>;
```

---

## 6. TSConfig Settings

Based on Matt Pocock's [TSConfig Cheat Sheet](https://www.totaltypescript.com/tsconfig-cheat-sheet):

```json
{
  "compilerOptions": {
    // Base Options
    "esModuleInterop": true,
    "skipLibCheck": true,
    "target": "es2022",
    "allowJs": true,
    "resolveJsonModule": true,
    "moduleDetection": "force",
    "isolatedModules": true,
    "verbatimModuleSyntax": true,

    // Strictness (IMPORTANT)
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,

    // For libraries
    "declaration": true,
    "declarationMap": true,

    // Module resolution
    "module": "NodeNext",
    "moduleResolution": "NodeNext"
  }
}
```

### Key strictness options

| Option                     | Description                                  |
| -------------------------- | -------------------------------------------- |
| `strict`                   | Enables all strict type checking             |
| `noUncheckedIndexedAccess` | Array/object access returns `T \| undefined` |
| `noImplicitOverride`       | Requires `override` keyword in subclasses    |

---

## 7. Zod Schema Patterns

For runtime validation with Zod, infer types from schemas:

```typescript
import { z } from "zod";

// ✅ DO: Define schema first, infer type
const UserSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  email: z.string().email(),
});

type User = z.infer<typeof UserSchema>;

// ❌ DON'T: Duplicate type definition
type User = {
  id: string;
  name: string;
  email: string;
};

const UserSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  email: z.string().email(),
});
```

---

## 8. Result Pattern

Use discriminated unions for error handling:

```typescript
// ✅ DO: Use Result type for fallible operations
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

// Usage
const parseConfig = (raw: string): Result<Config, ParseError> => {
  try {
    return ok(JSON.parse(raw));
  } catch (e) {
    return err(new ParseError("Invalid JSON"));
  }
};

// Type-safe consumption
const result = parseConfig(input);
if (result.ok) {
  console.log(result.value); // Config
} else {
  console.error(result.error); // ParseError
}
```

---

## 9. Import Conventions

```typescript
// ✅ DO: Use import type for type-only imports
import type { User, Config } from "./types";
import { processUser } from "./utils";

// ✅ DO: Separate type imports from value imports
import { z } from "zod";
import type { ZodSchema } from "zod";

// ❌ DON'T: Mix type and value imports (when verbatimModuleSyntax is enabled)
import { User, processUser } from "./module"; // If User is only a type, this fails
```

---

## 10. Naming Conventions

```typescript
// Types: PascalCase
type AnalysisResult = { ... };
type YARAMatch = { ... };

// Type parameters: Single uppercase letter or descriptive PascalCase
type Result<T, E> = ...;
type Container<TValue> = ...;

// Constants with as const: SCREAMING_SNAKE_CASE
const MAX_FILE_SIZE = 100_000_000 as const;

// Schema variables: PascalCase + Schema suffix
const UserSchema = z.object({ ... });
const AnalysisResultSchema = z.object({ ... });
```

---

## 11. Advanced Patterns

### Branded Types

Create nominally-typed primitives to prevent mixing incompatible values:

```typescript
// Brand pattern - prevents mixing different ID types
type Brand<K, T> = K & { __brand: T };

type UserId = Brand<string, "UserId">;
type ProductId = Brand<string, "ProductId">;

const createUserId = (id: string): UserId => id as UserId;
const createProductId = (id: string): ProductId => id as ProductId;

const userId = createUserId("user-123");
const productId = createProductId("prod-456");

function getUser(id: UserId) {
  /* ... */
}

getUser(userId); // ✅ OK
getUser(productId); // ❌ Error - ProductId not assignable to UserId
```

### Builder Pattern with Fluent API

```typescript
type RequestBuilder<T extends Record<string, unknown> = {}> = {
  method: <M extends string>(method: M) => RequestBuilder<T & { method: M }>;
  url: <U extends string>(url: U) => RequestBuilder<T & { url: U }>;
  body: <B>(body: B) => RequestBuilder<T & { body: B }>;
  build: T extends { method: string; url: string }
    ? () => { method: T["method"]; url: T["url"]; body?: T["body"] }
    : never;
};

// Usage - TypeScript enforces required fields
const request = createBuilder()
  .method("POST")
  .url("/api/users")
  .body({ name: "Alice" })
  .build(); // ✅ OK

const invalid = createBuilder().method("GET").build(); // ❌ Error - url is required
```

### Template Literal Types

```typescript
// Create type-safe event names
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";
type ApiVersion = "v1" | "v2";
type Endpoint = `/${ApiVersion}/${string}`;

type ApiRoute = `${HttpMethod} ${Endpoint}`;

const route: ApiRoute = "POST /v1/users"; // ✅ OK
const invalid: ApiRoute = "PATCH /users"; // ❌ Error
```

### Recursive Types

```typescript
// JSON type (recursive)
type JSONValue =
  | string
  | number
  | boolean
  | null
  | JSONValue[]
  | { [key: string]: JSONValue };

// Path builder for nested objects
type PathOf<T> = T extends object
  ? {
      [K in keyof T]: K extends string
        ? T[K] extends object
          ? K | `${K}.${PathOf<T[K]>}`
          : K
        : never;
    }[keyof T]
  : never;

type User = {
  profile: {
    address: {
      city: string;
    };
  };
};

type UserPaths = PathOf<User>; // 'profile' | 'profile.address' | 'profile.address.city'
```

### Conditional Types for Flexibility

```typescript
// Extract async return type
type Awaited<T> = T extends Promise<infer U> ? U : T;

// Make properties nullable
type Nullable<T> = {
  [K in keyof T]: T[K] | null;
};

// Deep partial
type DeepPartial<T> = T extends object
  ? {
      [P in keyof T]?: DeepPartial<T[P]>;
    }
  : T;
```

### Object Lookups vs If-Else Chains

Prefer type-safe object mappings over long if-else chains or switch statements. This pattern provides:

- **Exhaustiveness checking** - TypeScript ensures all cases are handled
- **Better readability** - Declarative configuration vs imperative logic
- **Reduced complexity** - Fewer branches mean lower cognitive complexity scores

```typescript
// ❌ DON'T: Long if-else chains
function getRiskColor(level: RiskLevel): string {
  if (level === "critical") return "#ff0000";
  if (level === "high") return "#ff6600";
  if (level === "medium") return "#ffcc00";
  if (level === "low") return "#00cc00";
  return "#808080"; // Easy to forget a case!
}

// ✅ DO: Type-safe object lookup with satisfies
type RiskLevel = "critical" | "high" | "medium" | "low";

const RISK_COLORS = {
  critical: "#ff0000",
  high: "#ff6600",
  medium: "#ffcc00",
  low: "#00cc00",
} as const satisfies Record<RiskLevel, string>;

function getRiskColor(level: RiskLevel): string {
  return RISK_COLORS[level]; // Exhaustive - TypeScript errors if a case is missing
}
```

### Exhaustive Mappings with `satisfies`

The `satisfies` operator ensures your mapping covers all cases while preserving literal types:

```typescript
type Severity = "critical" | "high" | "medium" | "low";

// This will ERROR if you forget a case
const SEVERITY_WEIGHTS = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  // If you add a new Severity value, TypeScript will error here
} as const satisfies Record<Severity, number>;

// Usage - guaranteed to be defined
const weight = SEVERITY_WEIGHTS[severity]; // type: 100 | 75 | 50 | 25
```

### Handler Mappings for Command Patterns

Replace switch statements with handler objects for better extensibility:

```typescript
// ❌ DON'T: Switch statement for handlers
function handleAction(action: Action): void {
  switch (action.type) {
    case "analyze":
      runAnalysis(action.payload);
      break;
    case "report":
      generateReport(action.payload);
      break;
    // Easy to forget a case...
  }
}

// ✅ DO: Handler mapping with exhaustiveness
type ActionType = "analyze" | "report" | "triage";

const ACTION_HANDLERS = {
  analyze: (payload: AnalyzePayload) => runAnalysis(payload),
  report: (payload: ReportPayload) => generateReport(payload),
  triage: (payload: TriagePayload) => runTriage(payload),
} as const satisfies Record<ActionType, (payload: unknown) => void>;

function handleAction(action: Action): void {
  ACTION_HANDLERS[action.type](action.payload);
}
```

### Threshold-Based Scoring with Declarative Rules

Replace cascading if-else threshold checks with declarative rule arrays:

```typescript
// ❌ DON'T: Cascading if-else for thresholds
function getScore(value: number): number {
  if (value > 100) return 50;
  if (value > 50) return 30;
  if (value > 20) return 15;
  if (value > 0) return 5;
  return 0;
}

// ✅ DO: Declarative threshold rules
type ThresholdRule = readonly [threshold: number, score: number];

const SIZE_SCORE_RULES: readonly ThresholdRule[] = [
  [100, 50], // > 100 → 50 points
  [50, 30], // > 50 → 30 points
  [20, 15], // > 20 → 15 points
  [0, 5], // > 0 → 5 points
] as const;

function scoreByThreshold(
  value: number,
  rules: readonly ThresholdRule[],
): number {
  for (const [threshold, score] of rules) {
    if (value > threshold) return score;
  }
  return 0;
}

// Usage
const score = scoreByThreshold(value, SIZE_SCORE_RULES);
```

### When to Use Each Pattern

| Pattern          | Use When                                                |
| ---------------- | ------------------------------------------------------- |
| Object Lookup    | Mapping discrete values to values (enums, status codes) |
| Handler Mapping  | Dispatching to different functions based on type        |
| Threshold Rules  | Cascading numeric comparisons                           |
| Switch Statement | Only when fall-through is intentional                   |
| If-Else          | Complex conditions that can't be expressed as lookups   |

---

## 12. Testing Patterns

### Type Testing with `expectTypeOf`

```typescript
import { expectTypeOf } from "vitest";

test("function returns correct type", () => {
  const result = processData("/path");

  expectTypeOf(result).toEqualTypeOf<Promise<DataResult>>();
});

test("Result discriminated union narrows correctly", () => {
  const result: Result<string, Error> = ok("success");

  if (result.ok) {
    expectTypeOf(result.value).toBeString();
    // @ts-expect-error - error shouldn't exist on ok branch
    result.error;
  }
});
```

### Mock Typing

```typescript
// Type-safe mocks
type MockedFunction<T extends (...args: any[]) => any> = {
  (...args: Parameters<T>): ReturnType<T>;
  mockReturnValue: (value: ReturnType<T>) => void;
  mockResolvedValue: ReturnType<T> extends Promise<infer U>
    ? (value: U) => void
    : never;
};

// Usage
const mockFetch: MockedFunction<typeof fetch> = vi.fn();
mockFetch.mockResolvedValue(new Response("OK"));
```

---

## 13. Anti-Patterns to Avoid

### ❌ DON'T: Use `any`

```typescript
// ❌ NEVER do this
function processData(data: any) {
  return data.foo.bar; // No type safety
}

// ✅ DO: Use unknown and narrow
function processData(data: unknown) {
  if (isDataValid(data)) {
    return data.foo.bar; // Type-safe after validation
  }
  throw new Error("Invalid data");
}
```

### ❌ DON'T: Overuse `as` type assertions

```typescript
// ❌ DON'T: Lie to TypeScript
const user = {} as User;
user.name.toUpperCase(); // Runtime error!

// ✅ DO: Validate and construct properly
const user: User = {
  id: "123",
  name: "Alice",
  email: "alice@example.com",
};
```

### ❌ DON'T: Use `!` non-null assertion carelessly

```typescript
// ❌ DON'T: Assume value exists
function getUser(id: string) {
  return users.find((u) => u.id === id)!; // Might be undefined!
}

// ✅ DO: Handle null/undefined explicitly
function getUser(id: string): User | undefined {
  return users.find((u) => u.id === id);
}

// ✅ OR: Throw if not found
function getUserOrThrow(id: string): User {
  const user = users.find((u) => u.id === id);
  if (!user) throw new Error(`User ${id} not found`);
  return user;
}
```

### ❌ DON'T: Use enums (in most cases)

```typescript
// ❌ DON'T: Use enums (they emit runtime code)
enum Color {
  Red = "red",
  Blue = "blue",
}

// ✅ DO: Use const objects with as const
const COLOR = {
  RED: "red",
  BLUE: "blue",
} as const;

type Color = (typeof COLOR)[keyof typeof COLOR];
```

### ❌ DON'T: Duplicate type information

```typescript
// ❌ DON'T: Maintain parallel type and schema
type User = {
  id: string;
  name: string;
};

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
});

// ✅ DO: Single source of truth
const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
});

type User = z.infer<typeof UserSchema>;
```

### ❌ DON'T: Use optional chaining to hide bugs

```typescript
// ❌ DON'T: Use ?. to sweep undefined under the rug
function displayUserName(user: User | undefined) {
  console.log(user?.name?.toUpperCase()); // Might log undefined
}

// ✅ DO: Handle undefined explicitly
function displayUserName(user: User | undefined) {
  if (!user) {
    console.log("No user");
    return;
  }
  console.log(user.name.toUpperCase());
}
```

### ❌ DON'T: Use long if-else chains for value mapping

```typescript
// ❌ DON'T: Long if-else chains for discrete value mapping
function getStatusLabel(status: Status): string {
  if (status === "pending") return "Pending Review";
  if (status === "approved") return "Approved";
  if (status === "rejected") return "Rejected";
  return "Unknown"; // No exhaustiveness checking!
}

// ✅ DO: Use type-safe object lookup
const STATUS_LABELS = {
  pending: "Pending Review",
  approved: "Approved",
  rejected: "Rejected",
} as const satisfies Record<Status, string>;

function getStatusLabel(status: Status): string {
  return STATUS_LABELS[status]; // Exhaustive - errors if case missing
}
```

---

## 14. Project Structure Recommendations

### Organize by feature, not by type

```text
src/
  features/
    auth/
      types.ts
      api.ts
      hooks.ts
      components/
    users/
      types.ts
      api.ts
      hooks.ts
      components/
  shared/
    types/
      utils.ts
      result.ts
    utils/
      validation.ts
    components/
```

### Shared types location

```typescript
// src/shared/types/utils.ts
export type Prettify<T> = { [K in keyof T]: T[K] } & {};
export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

// src/shared/types/common.ts
export type ID = string;
export type Timestamp = number;
export type DeepReadonly<T> = { readonly [K in keyof T]: DeepReadonly<T[K]> };
```

---

## 15. Editor Configuration

### VSCode Settings

Create `.vscode/settings.json`:

```json
{
  "typescript.tsdk": "node_modules/typescript/lib",
  "typescript.enablePromptUseWorkspaceTsdk": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": "explicit"
  },
  "typescript.preferences.preferTypeOnlyAutoImports": true,
  "typescript.inlayHints.parameterNames.enabled": "all",
  "typescript.inlayHints.functionLikeReturnTypes.enabled": true
}
```

### Cursor/AI Rules

Create `.cursorrules` or `.cursor/rules`:

```markdown
# TypeScript Rules

- Use `type` instead of `interface` by default
- Add return types to all exported functions
- Use `as const` for literal values that shouldn't widen
- Use `satisfies` when you need exact types with validation
- Never use `any` - use `unknown` instead
- Prefer discriminated unions over optional properties
- Use Zod for runtime validation, infer types from schemas
- Follow the Result pattern for error handling
- Enable noUncheckedIndexedAccess in tsconfig
```

---

## 16. Performance Considerations

### Type Complexity

```typescript
// ❌ AVOID: Deeply nested conditional types (slow compilation)
type DeepConditional<T> = T extends A
  ? B extends C
    ? D extends E
      ? F
      : G
    : H
  : I;

// ✅ DO: Break into smaller types
type StepOne<T> = T extends A ? B : never;
type StepTwo<T> = T extends C ? D : never;
type Result<T> = StepTwo<StepOne<T>>;
```

### Avoid Excessive Union Types

```typescript
// ❌ AVOID: Unions with 100+ members
type EventType = 'click' | 'hover' | 'focus' | /* ...97 more */;

// ✅ DO: Use string if truly unbounded
type EventType = string;

// ✅ OR: Use branded types for subsets
type ClickEvent = Brand<string, 'ClickEvent'>;
type HoverEvent = Brand<string, 'HoverEvent'>;
```

---

## 17. Additional Resources

### Recommended Tools

- **[@total-typescript/ts-reset](https://www.totaltypescript.com/ts-reset)** - Improves built-in TypeScript typings
- **[Zod](https://zod.dev/)** - TypeScript-first schema validation
- **[Vitest](https://vitest.dev/)** - Fast, modern test runner with TypeScript support
- **[Biome](https://biomejs.dev/)** - Fast linter and formatter (Prettier + ESLint replacement)

### Learning Resources

- [Total TypeScript](https://www.totaltypescript.com/) - Matt Pocock's comprehensive TypeScript courses
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html) - Official documentation
- [Type Challenges](https://github.com/type-challenges/type-challenges) - Practice type manipulation

---

## References

- [Total TypeScript](https://www.totaltypescript.com/)
- [Type vs Interface](https://www.totaltypescript.com/type-vs-interface-which-should-you-use)
- [TSConfig Cheat Sheet](https://www.totaltypescript.com/tsconfig-cheat-sheet)
- [The satisfies Operator](https://www.totaltypescript.com/clarifying-the-satisfies-operator)
- [as const](https://www.totaltypescript.com/concepts/as-const)
- [TS Reset](https://www.totaltypescript.com/ts-reset)

---

Last Updated: January 17, 2026
