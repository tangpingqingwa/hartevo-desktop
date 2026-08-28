use hartevo_salesforce_crm_result_plugin::{
    SALESFORCE_CRM_RESULT_CONTRACT_VERSION, SalesforceCrmResultContract, contract_digest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    SalesforceCrmResultContract::baseline()?;
    println!(
        "salesforce-crm-result contract={} digest={}",
        SALESFORCE_CRM_RESULT_CONTRACT_VERSION,
        contract_digest().as_str()
    );
    Ok(())
}
