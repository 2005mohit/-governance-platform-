// Class-method definitions, not calls. None of these may fire.
class A {
  delete(id) {}
  async terminate(id) {}
  static transfer(id) {}
  get x() {
    return 1;
  }
  set x(value) {}
}
