# Discrete Task Breakdown Meeting

## Agenda Items

- Breakdown High-Level Tasks into discrete tasks (per section 5 of the project plan)
- Story Point each task (aiming to complete X number of story points on a weekly interval)
- Assign Tasks for next week interval

## Action Items

N/A

## Additional Notes

N/A

## Item Breakdown

### Phase 1: Scoping and Requirements
- **Define Assumptions:** Outline any assumptions made by the team in developing the system
- **Define Constraints:** Outline any constraints or limiting factors that define the project’s boundaries
- **Stakeholder Alignment:** Map any regulatory requirements (Executive Order 14028) to the system’s functional requirements
- **Success Criteria:** Establish quantitative success criteria for all KPIs

### Phase 2: Architecture and Design
- **Design CI/CD Pipeline Workflow:** Map a series of 3rd party open-source tools within a GitHub Actions workflow to conduct application build process. This involves finalizing the high-level design and selecting the 3rd party open-source software tools
- **Schema Definition:** Define a unified schema for normalizing deterministic outputs from SAST and SBOM stages for ingestion into ML classification. This bridges the gap between the traditional deterministic CI/CD stages and the ML classification
- **Design ML-Classification Tool:** Per the schema definition, map SAST and SBOM output into a ML inference tool to compute deployment gate decisions

### Phase 3: Parallel Execution
- **Develop CI/CD Pipeline Workflow:** Develop and deploy the hardened CI/CD environment to a functional GitHub repository.
- **Develop ML-Classification Tool:** Develop and deploy ML-Classification model against sample outputs per the unified schema definition
- **Incremental Documentation:** Documentation will be updated incrementally as progress is made, including iterative metrics collection for each of the KPIs
- **Incremental Research:** Ongoing research should be conducted to ensure that project developments and direction align with functional requirements

### Phase 4: Integration and Validation
- **Integrate Decision Components:** Integrate the ML-Classification tool into the CI/CD pipeline’s enforcement gate stage. This should complete the end-to-end pipeline
- **Quantify KPIs:** Conduct iterative analysis of the pipeline with a variety of software inputs to validate the efficacy of the pipeline
- **Qualify And Quantify Risk:** Based upon metrics captured from the pipeline, gauge any qualitative and quantitative risks posed by using the pipeline
- **Access Auditability and Compliance:** Ensure that build process, SAST, SBOM, and ML classification decisions are adequately logged. Ensure logs are immutable and include proper retention for compliance

### Phase 5: Finalization
- **Scope Freeze:** Transition from feature development to bug fixing and review 2–4 weeks before final submission
- **Final Integrity Verification:** Conduct and document final end-to-end walkthrough to ensure the entire system satisfies all functional requirements
- **Technical Documentation:** Finalize all end-product deliverables
