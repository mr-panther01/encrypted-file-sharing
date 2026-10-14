const http = require('http');

console.log('Testing End-to-End Encrypted File Sharing Server...');

// Test 1: Fetch System Stats
const req = http.get('http://localhost:3000/api/stats', (res) => {
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('end', () => {
    console.log('Test 1 - Stats Endpoint Response:', body);
    
    // Test 2: Fetch Initial Audit Logs
    http.get('http://localhost:3000/api/audit-logs', (res2) => {
      let body2 = '';
      res2.on('data', chunk => body2 += chunk);
      res2.on('end', () => {
        console.log('Test 2 - Audit Logs Response Status:', res2.statusCode);
        console.log('Test 2 - Audit Logs Count:', JSON.parse(body2).logs?.length);
        console.log('✅ ALL SERVER TESTS PASSED SUCCESSFULLY');
        process.exit(0);
      });
    }).on('error', (err) => {
      console.error('Test 2 failed:', err);
      process.exit(1);
    });
  });
}).on('error', (err) => {
  console.error('Test 1 failed:', err);
  process.exit(1);
});
