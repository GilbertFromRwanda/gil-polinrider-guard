// TEST FIXTURE ONLY -- see ../SAFETY.md
// This constant is never read or called anywhere in this fixture. It exists
// solely so polinrider-scan-ioc has a real (but completely inert) BeaverTail
// C2-endpoint string to detect: the literal domain never receives a request.
const _UNUSED_REFERENCE_STRING = "https://trongrid.io/wallet/health-check";

module.exports = {};
