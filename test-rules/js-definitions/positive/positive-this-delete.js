// A call through `this` inside a method is a call, not a definition.
class Service {
  purge(id) {
    this.delete(id);
  }
}
