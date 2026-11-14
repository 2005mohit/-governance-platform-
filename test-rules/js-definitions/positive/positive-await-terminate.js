// An awaited call on a non-benign receiver must still fire.
async function run(mailer, x) {
  await mailer.terminate(x);
}
