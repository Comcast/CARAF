# Use Case Categories
Cryptographic systems can be deployed in various scenarios, each with unique requirements and constraints. This page categorizes these use cases to help identify relevant performance metrics. Categories are important because they help in understanding the specific needs and challenges of different deployment environments. A real deployment can fall into multiple categories. For example, an IoT device can fall under Low Computational Power, Software-Based Cryptographic Implementations, and High Energy Constraints use cases.
To provide a quick overview, the table below summarizes key categories, their subcategories, example use cases, and links to detailed sections:

### Categorization Summary Table

<table>
  <thead>
    <tr>
      <th style="width:10%">Category</th>
      <th style="width:15%">Subcategory</th>
      <th style="width:45%">Description</th>
      <th style="width:30%">Example Use Cases</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>🔋 Energy Constraints</td>
      <td>Very High Energy Constraints</td>
      <td>- <strong>Energy-Harvesting:</strong> Powered by ambient sources like solar or RF.<br>- <strong>Ultra-Low Power:</strong> Runs on minimal energy, often battery-based.</td>
      <td>Environmental sensors, solar-powered wearables)</td>
    </tr>
    <tr>
      <td></td>
      <td>High Energy Constraints</td>
      <td>Slightly higher consumption, but still energy-efficient by design.</td>
      <td>Smart bulbs, fitness trackers</td>
    </tr>
    <tr>
      <td></td>
      <td>Moderate Energy Constraints</td>
      <td>Balance power and performance; support limited local processing</td>
      <td>Gateway Devices, Edge Devices</td>
    </tr>
    <tr>
      <td></td>
      <td>Low Energy Constraints</td>
      <td>Handles intensive processing and large data workloads.</td>
      <td>Local Servers, Heavy Edge Devices</td>
    </tr>
    <tr>
      <td></td>
      <td>Minimal Energy Constraints</td>
      <td>Offer extensive computational power and storage with minimal relative constraints.</td>
      <td>Cloud Resources, Data Centers</td>
    </tr>
    <tr>
      <td>🌐 Network Performance</td>
      <td>Low Latency Use Cases</td>
      <td>Minimizes delay for real-time responsiveness</td>
      <td>Gaming consoles, video conferencing systems, autonomous vehicles</td>
    </tr>
    <tr>
      <td></td>
      <td>Moderate Latency Use Cases</td>
      <td>Optimized for both latency and data handling.</td>
      <td>Smart home hubs, industrial IoT gateways</td>
    </tr>
    <tr>
      <td></td>
      <td>High Latency Use Cases</td>
      <td>Delay-tolerant, non-real-time operations.</td>
      <td>Environmental sensors, certain types of wearables</td>
    </tr>
    <tr>
      <td></td>
      <td>High Throughput Use Cases</td>
      <td>Fast transfer of large data volumes.</td>
      <td>Streaming devices, data backup systems, large file transfer applications</td>
    </tr>
    <tr>
      <td></td>
      <td>Moderate Throughput Use Cases</td>
      <td>Steady data flow for typical applications.</td>
      <td>Consumer wearables, health monitoring devices</td>
    </tr>
    <tr>
      <td></td>
      <td>Low Throughput Use Cases</td>
      <td>Minimal data needs, low-bandwidth devices.</td>
      <td>Simple sensors, RFID tags</td>
    </tr>
    <tr>
      <td>🧠 Computational Resources</td>
      <td>High Computational Power</td>
      <td>Handles complex, intensive workloads.</td>
      <td>Servers, High-Performance Computing Systems</td>
    </tr>
    <tr>
      <td></td>
      <td>Moderate Computational Power</td>
      <td>Balanced performance for general tasks.</td>
      <td>Laptops, Smart Home Hubs</td>
    </tr>
    <tr>
      <td></td>
      <td>Low Computational Power</td>
      <td>Basic processing for simple functions.</td>
      <td>Basic Sensors, Simple IoT Devices</td>
    </tr>
    <tr>
      <td>🔐 Security Requirements</td>
      <td>High Security Use Cases</td>
      <td>Protects critical, sensitive data.</td>
      <td>Financial systems, healthcare devices, government communications</td>
    </tr>
    <tr>
      <td></td>
      <td>Moderate Security Use Cases</td>
      <td>Balanced protection and performance.</td>
      <td>Smart home devices, consumer electronics</td>
    </tr>
    <tr>
      <td></td>
      <td>Minimum Security Use Cases</td>
      <td>Low-risk, non-sensitive environments.</td>
      <td>Environmental sensors, basic IoT devices in public domains</td>
    </tr>
    <tr>
      <td>⚙️ Cryptographic Implementation Method</td>
      <td>Hardware-Based Cryptographic Use Cases</td>
      <td>Dedicated hardware for speed and security.</td>
      <td>HSMs, Cryptographic Accelerators, FPGA-based Encryption</td>
    </tr>
    <tr>
      <td></td>
      <td>Software-Based Cryptographic Use Cases</td>
      <td>Flexible, platform-wide encryption.</td>
      <td>OpenSSL, Software-based Encryption on General-Purpose Processors</td>
    </tr>
  </tbody>
</table>






---

To understand the metrics and how they apply to these categories, refer to the [Categories vs Metrics table](./Categories-vs-Metrics.md) page.

