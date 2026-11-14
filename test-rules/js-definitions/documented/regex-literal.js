// Documented limitation: regex literals are not lexed as their own state.
// Current behaviour: this pattern is treated as code and fires both action
// rules. Item 3's fix-up records it; it does not change this behaviour.
const pattern = /delete(id)/;
