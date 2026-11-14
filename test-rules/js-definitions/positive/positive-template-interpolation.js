// A call inside a template interpolation is code, not literal text.
const message = `Deleted ${db.delete(id)} rows`;
