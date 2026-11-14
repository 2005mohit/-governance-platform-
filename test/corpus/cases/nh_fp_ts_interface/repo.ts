interface Repository {
  delete(id: string): Promise<void>;
}
