class Repository {
  delete(id) {
    return this.items.splice(id, 1);
  }
}
