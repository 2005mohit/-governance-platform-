// Object-literal method definitions, not calls. None of these may fire.
const o = {
  delete(id) {},
  terminate: async (id) => {},
  transfer: function (id) {},
  remove: function () {}
};
