import streamlit as st
import os
import re
import glob
import json
from enum import Enum
from typing import List, Dict, Union
from pydantic import BaseModel, Field
from email import policy
from email.parser import BytesParser
from openai import OpenAI



# ========== MODELS ==========

class Campaign(str, Enum):
    BIG_BOSS = "big_boss"
    VELVET_SHOP = "velvet_shop"
    JOB_DREAMER = "job_dreamer"
    NON_MALICIOUS = "non_malicious"

class CampaignType(BaseModel):
    category: Campaign
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    confidence_for_each: Dict[Campaign, float] = Field(default_factory=dict)
    how_did_confidence_computed_in_detail: str
api_key = st.secrets["API_KEY"]
client=OpenAI(api_key=api_key)


    
# with Mistral(
#     api_key="rtwv2klbsDF9Q8tWV88LOPZHD5uSXlgt",
# ) as mistral:

#     res = mistral.chat.complete(model="mistral-small-latest", messages=[
#         {
#             "content": "Who is the best French painter? Answer in one short sentence.",
#             "role": "user",
#         },
#     ], stream=False)


# ========== PARSE .EML + IOC EXTRACTION ==========

def extract_iocs_from_headers(msg) -> Dict[str, List[str]]:
    iocs = {
        "sender_ips": [],
        "email_addresses": [],
        "domains": [],
        "urls": [],
        "message_ids": [],
        "authentication": []
    }

    for header in msg.get_all("Received", []):
        iocs["sender_ips"].extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header))

    for field in ["From", "Reply-To", "Return-Path"]:
        raw = msg.get(field, "")
        emails = re.findall(r'[\w\.-]+@[\w\.-]+', raw)
        iocs["email_addresses"].extend(emails)
        iocs["domains"].extend([e.split("@")[1] for e in emails if "@" in e])

    list_unsub = msg.get("List-Unsubscribe", "")
    iocs["urls"].extend(re.findall(r'https?://[^\s,>]+', list_unsub))

    msg_id = msg.get("Message-ID", "")
    if msg_id:
        iocs["message_ids"].append(msg_id)

    for auth_header in ["Received-SPF", "Authentication-Results"]:
        value = msg.get(auth_header, "")
        if value:
            iocs["authentication"].append(value)

    for key in iocs:
        iocs[key] = list(set(iocs[key]))

    return iocs

def parse_eml_file(filepath: str) -> Dict:
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    iocs = extract_iocs_from_headers(msg)

    return {
        "File": os.path.basename(filepath),
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Body": body.strip(),
        "IOCs": iocs
    }

def parse_eml_folder(folder_path: str) -> List[Dict]:
    eml_files = glob.glob(os.path.join(folder_path, "*.eml"))
    return [parse_eml_file(file) for file in eml_files]

# ========== CLASSIFICATION ==========

def build_email_prompt(email: Dict[str, str]) -> str:
    email_content = f"""
From: {email['From']}
To: {email['To']}
Subject: {email['Subject']}

{email['Body']}
"""
    return f"""
You are a cybersecurity analyst. Your task is to classify incoming emails into phishing campaigns based on known patterns. We currently track multiple campaigns. For now, classify emails into one of the following:

big_boss

Description: Emails impersonate "CEO Amin Nasser, CEO of Aramco", asking the recipient to respond urgently.

Common traits: Urgent tone, request for quick response, impersonation of executive.

Example:
From: Amin alnaser noOne@flekege.com
To: Ali team@example.com
Subject: Urgent request

Dear Ali, call me asap, I need to discuss the project with you. It is very important and I need your input on this matter.

category: big_boss

velvet_shop

Description: Emails deliver malicious Excel attachments that automatically run embedded macros when opened. These emails typically masquerade as legitimate business correspondence such as quotes or invoices, without using password protection. The goal is to socially engineer the recipient into opening the file based on urgency or routine business processes.

Common traits: Excel attachment, plausible business context (e.g., RFQ, invoice, pricing), urgent or action-oriented language, no password used.

Example:
Subject: RE: Quotation for Q3 Equipment Order

Dear [Recipient Name],

Please find attached the updated quotation for your review. Let us know if you have any questions or need adjustments to the pricing.

Attachment: Q3_Equipment_Quote.xlsx

category: velvet_shop

Your task:

Given an email, classify it into one of these categories:

"big_boss"

"velvet_shop"

"non_malicious" (if it doesn't fit either campaign)

Return ONLY a JSON object with the following fields:

"category": one of ["big_boss", "velvet_shop", "non_malicious"]

"confidence": float from 0.0 to 1.0 indicating classification confidence

"confidence_for_each": for each category, 0.0 means no confidence, 1.0 means high confidence


"how_did_confidence_computed_in_detail": 1–2 sentence explanation of how the confidence was computed


"description": 1–2 sentence rationale for the classification

{email_content}
Only respond with a **valid JSON object**. No extra text or explanations outside the JSON.
"""

def parse_llm_response(response_text: str) -> CampaignType:
    return CampaignType.model_validate_json(response_text.strip())

def classify_single_email(email: Dict[str, str]) -> Dict[str, Union[str, CampaignType]]:
    prompt = build_email_prompt(email)

    response = client.chat.completions.create(
        model="gpt-5.1",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
    )

    raw_output = response.choices[0].message.content.strip()

    try:
        classification = parse_llm_response(raw_output)
        print(f"Classification for {email['File']}: {classification}")
        return {**email, "classification": classification}
    except Exception as e:
        return {**email, "error": str(e), "raw_output": raw_output}

# ========== STREAMLIT UI ==========

st.set_page_config(page_title="CampMatch", layout="wide")
st.title("📧 CampMatch – AI-Powered Email Campaign Classifier")
st.markdown("Upload `.eml` files, parse them, extract IOCs, and classify each email into a known phishing campaign.")

st.subheader("📂 Step 1: Select Folder Containing `.eml` Files")
folder_path = st.text_input("Enter folder path with `.eml` files", "emails/")

if st.button("Run Analysis"):
    with st.spinner("Parsing and classifying emails..."):
        emails = parse_eml_folder(folder_path)
        results = [classify_single_email(email) for email in emails]

    st.success(f"Processed {len(results)} email(s).")

    st.subheader("📊 Results")
    for email in results:
        with st.expander(f"📁 {email['File']} - {email.get('classification', {}).category if 'classification' in email else '❌ Unclassified'}"):
            st.markdown(f"**From:** {email['From']}")
            st.markdown(f"**To:** {email['To']}")
            st.markdown(f"**Subject:** {email['Subject']}")
            st.markdown("**Body:**")
            st.code(email["Body"], language="text")

            if "classification" in email:
                cls = email["classification"]
                st.markdown(f"### 🧠 Classification")
                st.write(f"**confidence_for_each**: `{cls.confidence_for_each}`")
                st.write(f"**how_did_confidence_computed_in_detail**: `{cls.how_did_confidence_computed_in_detail}`")
                st.write(f"**Category**: `{cls.category}`")
                st.write(f"**Confidence**: `{cls.confidence}`")
                st.write(f"**Description**: {cls.description}")
            else:
                st.error(f"Classification Error: {email.get('error')}")
                st.text_area("Raw Output", email.get("raw_output", ""))

            st.markdown("### 🕵️‍♂️ Extracted IOCs")
            for key, values in email["IOCs"].items():
                if values:
                    st.markdown(f"**{key.replace('_', ' ').title()}**")
                    st.code("\n".join(values))
