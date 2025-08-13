// Load php-parser
const fs = require("fs");
const parser = require("php-parser");

// Parse PHP content passed via stdin
let inputData = "";
process.stdin.on("data", chunk => {
    inputData += chunk;
});
process.stdin.on("end", () => {
    try {
        const phpParser = new parser.Engine({
            parser: { extractDoc: true },
            ast: { withPositions: true }
        });

        const ast = phpParser.parseCode(inputData);

        // Collect line numbers that contain safe functions
        const SAFE_FUNCTIONS = [
            "htmlspecialchars",
            "filter_input",
            "password_hash",
            "mysqli_real_escape_string",
            "filter_var",
            "intval",
            "floatval"
        ];

        let safeLines = new Set();

        function traverse(node) {
            if (node && typeof node === "object") {
                if (node.kind === "call" && node.what && node.what.name && SAFE_FUNCTIONS.includes(node.what.name)) {
                    safeLines.add(node.loc.start.line);
                }
                for (let key in node) {
                    if (node[key] && typeof node[key] === "object") {
                        traverse(node[key]);
                    }
                }
            }
        }

        traverse(ast);

        process.stdout.write(JSON.stringify({ safeLines: Array.from(safeLines) }));
    } catch (err) {
        process.stderr.write(err.toString());
        process.exit(1);
    }
});
