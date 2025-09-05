# SIEM-Usecase
Welcome!
As a Security Operations Center (SOC) Analyst, I've dedicated considerable time to triaging alerts and analyzing the efficiency of various use cases, including data source assessment. Through my work in use case engineering, I've gained significant experience in refining these processes.

Below, you'll find a list of use cases that I personally built and tested in Splunk.

---

### Use Cases:

* Basic scanning
* Create Log from this particular host is not generated
* Analysing threat match activity with spl
* Detecting Horizontal and vertical scanning using splunk
* Log from this particular host is not generated
* Prototype Detecting RDP Brute-force
* simultaneous access to host
  
* * *
### **Refinement Flow**

1. **Assess the Use Case** – Analyze the objective and evaluate the detection capability and dependencies.

2. **Logic Development** – Develop the logic and define the dependencies.

3. **Testing on Live Environment** – Validate the logic against the last 90 days of data.

4. **Deploy as Test Alert in Real-time Environment** – Monitor the alert’s performance and efficiency (e.g., True Positives, False Positives).

5. **Continuous Improvement** – Iterate and enhance the use case based on observations.

6. **Make Primary** – Promote the test use case to primary by replacing the old one.

* * *

### **Use Case Life Cycle**

* **When Assessment is Needed**
  
  * During onboarding of a new data source.
  
  * When changes occur in parsing.

* **Use Case Assessment**
  
  * Understand the objective.
  
  * Verify whether the logic is accurately detecting the intended behavior.
  
  * Analyze logs for parsing errors or field accuracy.
