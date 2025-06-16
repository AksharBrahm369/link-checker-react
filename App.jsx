import { useState } from 'react';


import axios from 'axios';
import './App.css';
import { GOOGLE_API_KEY } from './config'; // 👈 Import your API key
import { VIRUSTOTAL_API_KEY } from './config'; // 👈 Import API key


function App() {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false); // 👈 Optional loading spinner
  const [scanResults, setScanResults] = useState({});

  const checkWebsite = async () => {
    if (!url) return;

    setLoading(true);
    setStatus(null);

    const requestBody = {
      client: {
        clientId: "yourcompany", // any name
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    try {
      const response = await axios.post(
       ` https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
        requestBody
      );

      // setScanResults(result.data.data.attributes.results); // 👈 Save full engine-wise result

      if (response.data && response.data.matches) {
        setStatus('❌ Unsafe (Threats Detected)');
      } else {
        setStatus('✅ Safe Website');
      }
    } catch (error) {
      console.error('Error checking site:', error);
      setStatus('⚠️ Error checking website');
    }

    setLoading(false);
  };

  return (
    <div className="app">
      <h1>🌐 Website Safety Checker</h1>

      <input
        type="text"
        placeholder="Enter website URL..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={checkWebsite} disabled={loading}>
        {loading ? 'Checking...' : 'Check'}
      </button>

      {status && <p className="status">{status}</p>}
      {Object.keys(scanResults).length > 0 && (
  <div className="report">
    <h3>Detailed Report:</h3>
    <ul>
      {Object.entries(scanResults).map(([engine, result]) => (
        <li key={engine}>
          <strong>{engine}:</strong>{' '}
          {result.category === 'malicious' && <span style={{ color: 'red' }}>❌ Malicious</span>}
          {result.category === 'suspicious' && <span style={{ color: 'orange' }}>⚠️ Suspicious</span>}
          {result.category === 'harmless' && <span style={{ color: 'green' }}>✅ Harmless</span>}
          {result.category === 'undetected' && <span>➖ Undetected</span>}
        </li>
      ))}
    </ul>
  </div>
)}

    </div>
  );
}

export default App; 