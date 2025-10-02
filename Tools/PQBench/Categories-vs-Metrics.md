# Categories vs. Metrics Mapping

This table provides a clear mapping between various use case categories and their relevant performance metrics. The goal is to help users quickly identify which metrics are important for different cryptographic use cases.

To find out your relevant metrics you can either use the **Metrics Mapping** table below or watch the video following that. For the latter option, you need to download the [HTML file](./Resources/usecase_metrics_mapping.html), open using your browser, select your usecase and get the relevant metrics as shown in the video.


## Metrics Mapping

<table border="1">
    <caption>
       <b> Short Text Reference: VH = Very High, H = High, M = Moderate, L = Low, MN = Minimal, HW = Hardware, SW = Software </b>
    </caption>
    <tr>
        <th rowspan="3">Metrics ⬇️</th>
        <th rowspan="3">Categories ➡️</th>
        <th colspan="5" rowspan="2">Energy Constraints</th>
        <th colspan="6">Network Performance</th>
        <th colspan="3" rowspan="2">Computational Resources</th>
        <th colspan="3" rowspan="2">Security Requirements</th>
        <th colspan="2" rowspan="2">Cryptographic Implementation</th>
    </tr>
    <tr>
        <th colspan="3">Latency</th>
        <th colspan="3">Throughput</th>
    </tr>
    <tr>
        <th>VH</th>
        <th>H</th>
        <th>M</th>
        <th>L</th>
        <th>MN</th>
        <th>L</th>
        <th>M</th>
        <th>H</th>
        <th>H</th>
        <th>M</th>
        <th>L</th>
        <th>H</th>
        <th>M</th>
        <th>L</th>
        <th>H</th>
        <th>M</th>
        <th>MN</th>
        <th>HW</th>
        <th>SW</th>
    </tr>
    <tr>
        <td rowspan="6">Network Performance</td>
        <td>Throughput</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Latency</td>
        <td>❌</td><td>✅</td><td>✅</td><td>❌</td><td>✅</td>
        <td>✅</td><td>✅</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Packet Loss</td>
        <td>❌</td><td>✅</td><td>✅</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>❌</td><td>✅</td><td>✅</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
    </tr>
    <tr>
        <td>Jitter</td>
        <td>❌</td><td>✅</td><td>✅</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>❌</td><td>✅</td><td>✅</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
    </tr>
    <tr>
        <td>Interoperability</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Scalability</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td rowspan="7">Computational Performance</td>
        <td>Overall Performance</td>
       <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Key Generation Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Signature Generation Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Verification Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Shared Key Derivation Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Encryption Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Decryption Time</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td rowspan="3">Memory Performance</td>
        <td>Key Size</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Signature Size</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>Memory Consumption</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td rowspan="1">Energy Consumption</td>
        <td>Energy Efficiency</td>
        <td>✅</td><td>✅</td><td>✅</td><td>✅</td><td>❌</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td rowspan="2">Compound Metrics</td>
        <td>Certificate Throughput</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    <tr>
        <td>TLS Throughput</td>
        <td>❌</td><td>✅</td><td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td><td>❌</td>
        <td>✅</td><td>✅</td><td>✅</td>
        <td>❌</td><td>❌</td><td>✅</td><td>✅</td><td>✅</td>
    </tr>
    
</table>

---

https://github.com/user-attachments/assets/cfcef5f2-cbc1-45dc-a076-95b3d9c985de

To get the metrics measurement guides , please visit the [metrics](./Performance-Metrics.md) page.
