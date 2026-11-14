// delete(id) in a line comment must not fire.
/* terminate(id) in a block comment must not fire. */
/**
 * JSDoc: transfer(id) is documentation, not a call.
 */
const a = "delete(id)";
const b = 'terminate(id)';
const c = `transfer(id)`;
