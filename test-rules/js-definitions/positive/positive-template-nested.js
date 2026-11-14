// A nested template inside an interpolation stays code.
const message = `outer ${`inner ${db.delete(id)}`}`;
