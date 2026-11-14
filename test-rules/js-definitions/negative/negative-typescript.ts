// TypeScript declarations and method signatures, not calls. None of these may fire.
interface Repo {
  delete(id: string): void;
  terminate(id: string): Promise<void>;
}

abstract class Base {
  abstract delete(id: string): void;
  abstract transfer(id: string): Promise<void>;
}

declare function terminate(id: string): void;

// Overload signature plus implementation: both are declarations, not calls.
function transfer(id: string): void;
function transfer(id: string) {
  return id;
}
