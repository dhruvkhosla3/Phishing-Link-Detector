
"use strict";

// ---------------------------------------------------------------------------
// Matrix Background (shared by index.html and history.html)
// ---------------------------------------------------------------------------

const canvas = document.getElementById("matrix");
const ctx = canvas ? canvas.getContext("2d") : null;

let matrixTimer = null;

function resizeCanvas() {
    if (!canvas || !ctx) return;

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

if (canvas && ctx) {
    const letters = Array.from(
        "アァイィウエオカガキギクグケゲコゴサザシスズセゼソゾタダチッヂヅテデトドナニヌネノハバパヒビブプヘベペボマミムメモヤユヨラリルレロワヲン"
    );

    const fontSize = 14;
    let drops = [];
    let matrixColor = "#00ffaa";   // changes to red on phishing detection

    function resetDrops() {
        resizeCanvas();

        const columns = Math.ceil(canvas.width / fontSize);
        drops = Array.from(
            { length: columns },
            () => Math.random() * -30
        );
    }

    function drawMatrix() {
        if (!canvas || !ctx) return;

        ctx.fillStyle = "rgba(0, 0, 0, 0.07)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = matrixColor;
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const character =
                letters[Math.floor(Math.random() * letters.length)];

            ctx.fillText(character, i * fontSize, drops[i] * fontSize);

            if (
                drops[i] * fontSize > canvas.height &&
                Math.random() > 0.975
            ) {
                drops[i] = 0;
            }

            drops[i]++;
        }
    }

    resetDrops();
    matrixTimer = window.setInterval(drawMatrix, 35);

    window.addEventListener("resize", resetDrops);

    // Expose a way for the checker to change the matrix colour.
    window.setMatrixColor = function(color) {
        matrixColor = color;
    };
}

// ---------------------------------------------------------------------------
// URL Validation and Normalization
// ---------------------------------------------------------------------------

function normalizeAndValidateUrl(input) {
    if (typeof input !== "string") {
        return { valid: false, error: "Please enter a valid URL." };
    }

    const value = input.trim();

    if (!value) {
        return { valid: false, error: "Please enter a URL or domain." };
    }

    if (value.length > 4096) {
        return { valid: false, error: "The URL is too long." };
    }

    // Reject whitespace and control characters.
    if (/[\s\u0000-\u001f\u007f]/u.test(value)) {
        return {
            valid: false,
            error: "URLs cannot contain spaces or control characters."
        };
    }

    // Accept domains without a scheme, such as example.com.
    const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value)
        ? value
        : `https://${value}`;

    let parsed;

    try {
        parsed = new URL(candidate);
    } catch {
        return {
            valid: false,
            error: "Please enter a valid web address."
        };
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        return {
            valid: false,
            error: "Only HTTP and HTTPS URLs are supported."
        };
    }

    // Do not accept embedded credentials such as
    // https://example.com@malicious.example/
    if (parsed.username || parsed.password) {
        return {
            valid: false,
            error: "URLs containing embedded credentials are not accepted."
        };
    }

    const hostname = parsed.hostname.toLowerCase();

    if (!hostname || hostname.length > 253) {
        return {
            valid: false,
            error: "Please enter a valid hostname."
        };
    }

    // Permit a normal DNS hostname or a valid IP address.
    // The URL constructor also validates IPv6 syntax.
    const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);

    if (isIPv4) {
        const octets = hostname.split(".").map(Number);

        if (octets.some(octet => octet > 255)) {
            return {
                valid: false,
                error: "The IP address is invalid."
            };
        }
    } else {
        const isIPv6 = hostname.startsWith("[") &&
                       hostname.endsWith("]");

        if (!isIPv6) {
            const labels = hostname.split(".");

            if (
                labels.length < 2 ||
                labels.some(label =>
                    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
                ) ||
                labels[labels.length - 1].length > 63
            ) {
                return {
                    valid: false,
                    error: "Please enter a valid domain name."
                };
            }
        }
    }

    return {
        valid: true,
        url: parsed.href,
        hostname
    };
}

// ---------------------------------------------------------------------------
// Phishing Checker
// ---------------------------------------------------------------------------

const urlInput = document.getElementById("urlInput");
const resultBox = document.getElementById("resultBox");

function showResult(message, className) {
    if (!resultBox) return;

    // Use textContent rather than injecting HTML.
    resultBox.textContent = message;
    resultBox.className = className;
}

function saveHistory(entry) {
    if (typeof historyAddEntry !== "function") return;

    try {
        historyAddEntry(entry);
    } catch (error) {
        console.error("Could not save scan history:", error);
    }
}

function setChecking(isChecking) {
    const button = document.getElementById("checkButton");

    if (!button) return;

    button.disabled = isChecking;
    button.textContent = isChecking ? "Checking..." : "Check URL";
}

function checkURL() {
    if (!urlInput || !resultBox) return;

    const rawInput = urlInput.value;
    const validation = normalizeAndValidateUrl(rawInput);

    if (!validation.valid) {
        showResult(validation.error, "warning");
        return;
    }

    const url = validation.url;

    showResult("Analyzing URL...", "loading");
    setChecking(true);

    fetch("/check_url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        body: JSON.stringify({ url })
    })
        .then(async response => {
            let data;

            try {
                data = await response.json();
            } catch {
                throw new Error("The server returned an invalid response.");
            }

            if (!response.ok) {
                throw new Error(
                    data.error || `Server error (${response.status}).`
                );
            }

            return data;
        })
        .then(data => {
            if (data.verdict !== "safe" && data.verdict !== "unsafe") {
                throw new Error(
                    "The server response does not contain a valid verdict."
                );
            }

            const keywords = Array.isArray(data.matched_keywords)
                ? data.matched_keywords
                : [];

            if (data.verdict === "unsafe") {
                const detail = keywords.length
                    ? `Threat indicator(s) detected: ${keywords.join(", ")}.`
                    : "This URL contains suspicious threat indicators.";

                showResult(`\u26A0 UNSAFE \u2014 ${detail}`, "warning");

                if (typeof window.setMatrixColor === "function") {
                    window.setMatrixColor("#ff3366");
                }

                saveHistory({
                    url,
                    status: "unsafe",
                    statusLabel: "UNSAFE",
                    detail,
                    checkType: "URL Threat Scan"
                });
            } else {
                showResult("\u2714 SAFE \u2014 No threat indicators detected in this URL.", "safe");

                if (typeof window.setMatrixColor === "function") {
                    window.setMatrixColor("#00ffaa");
                }

                saveHistory({
                    url,
                    status: "safe",
                    statusLabel: "SAFE",
                    detail: "No threat indicators were detected.",
                    checkType: "URL Threat Scan"
                });
            }
        })
        .catch(error => {
            showResult(
                error.message || "Server unavailable. Please try again.",
                "warning"
            );

            // Reset matrix to green on error
            if (typeof window.setMatrixColor === "function") {
                window.setMatrixColor("#00ffaa");
            }

            saveHistory({
                url,
                status: "error",
                statusLabel: "UNKNOWN/ERROR",
                detail: error.message || "Could not complete the scan.",
                checkType: "URL/Domain Scan"
            });
        })
        .finally(() => {
            setChecking(false);
        });
}

// ---------------------------------------------------------------------------
// Event Listeners
// ---------------------------------------------------------------------------

if (urlInput) {
    urlInput.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            event.preventDefault();
            checkURL();
        }
    });
}

const checkButton = document.getElementById("checkButton");

if (checkButton) {
    checkButton.addEventListener("click", checkURL);
}

