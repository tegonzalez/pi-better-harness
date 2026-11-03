/**
 * Test-host session lifecycle for harnesses that boot the extension in-process.
 *
 * The extension's teardown latch is module state: `session_shutdown` closes it and
 * only `session_start` reopens it (a spawn never does, so nothing that belongs to an
 * ended session lifetime can start work). A real host always starts a session before
 * a model can call a tool. Every in-process harness in a file shares that one module,
 * so a harness built after an earlier test's shutdown is torn down until its session
 * starts. `hostLikeSession` gives a harness that host behavior: the first tool call
 * after a shutdown fires the harness's own `session_start` handler (with the calling
 * context) first, and explicit `session_start` / `session_shutdown` calls keep
 * the latch in step. It changes nothing about what a test asserts.
 */
let moduleTornDown = false;

/** Wrap `pi.on` / `pi.registerTool` in place; call before the extension registers. `handlers` is the harness's Map or object of registered handlers. */
export function hostLikeSession(pi, handlers) {
    const on = pi.on.bind(pi);
    pi.on = (event, fn) => {
        if (event === "session_start") return on(event, (...args) => { moduleTornDown = false; return fn(...args); });
        if (event === "session_shutdown") return on(event, (...args) => { moduleTornDown = true; return fn(...args); });
        return on(event, fn);
    };
    const registerTool = pi.registerTool.bind(pi);
    pi.registerTool = (def) => registerTool({
        ...def,
        execute: async (...args) => {
            if (moduleTornDown) await (handlers instanceof Map ? handlers.get("session_start") : handlers.session_start)?.({}, args[4]);
            return def.execute(...args);
        },
    });
    return pi;
}
