import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

AUTHENTIC_SAMPLES = [
    "We are seeking a Software Development Engineer with 2+ years of experience in React, TypeScript, and Node.js. Comprehensive medical insurance, 401k/PF matching, annual paid time off, and competitive salary based on experience.",
    "Full-time Data Analyst position at Microsoft. Responsibilities include building PowerBI dashboards, SQL data pipelines, and analyzing user metrics. Requires Bachelor's in CS or Statistics. Apply through Microsoft Careers.",
    "Internship Opportunity: Machine Learning Research Intern. Candidate will work with PyTorch, TensorFlow, and large language models. 6-month paid internship with monthly stipend of 45,000 INR. Equal Opportunity Employer.",
    "Cloud Infrastructure Engineer at Tata Consultancy Services. Candidate must have hands-on experience in AWS, Kubernetes, and CI/CD pipelines. Background verification will be performed via TCS official corporate portal.",
    "Product Marketing Specialist at Infosys. Plan and execute B2B marketing campaigns, collaborate with sales teams, and analyze conversion funnels. Requires strong written English and communication skills.",
    "Cybersecurity Analyst at Deloitte. Responsibilities include threat intelligence analysis, SIEM log monitoring, and vulnerability assessments. Standard enterprise benefits package including gratuity, PF, and health cover.",
    "Backend Developer at Zomato. Design resilient microservices in Go and Python. Hands-on experience with Redis, PostgreSQL, and Kafka required. Competitive ESOPs and health insurance.",
    "Frontend Engineering Intern at Swiggy. 3 months duration, working on modern Next.js and Tailwind web apps. Monthly stipend 35,000 INR with potential Pre-Placement Offer (PPO). Official application via careers.swiggy.in.",
    "Junior Quality Assurance Engineer at Wipro. Develop automated test suites using Selenium and Cypress. Minimum educational qualification: B.Tech/B.E/MCA with 60% aggregate. No fees or deposits required."
]

FRAUDULENT_SAMPLES = [
    "Urgent hiring for online part time work from home. Earn 3000 to 8000 daily just by liking YouTube videos and rating hotels on Google Maps. No skills required. Contact HR on WhatsApp +62821445566 or Telegram @pooja_daily_earning.",
    "Selected for Software Trainee at TCS without any interview. Congratulations! Please deposit refundable security fee of 6500 INR for laptop dispatch and uniform kit to UPI ID tcs.hr@oksbi within 24 hours.",
    "Direct selection in Indigo Airlines Ground Staff. 100% selection guaranteed. 12th pass eligible, salary 45000 per month. Pay interview gate pass and registration fee 2500 rupees immediately to secure slot.",
    "Work from home data entry typing job. Earn 40000 monthly working only 2 hours a day. Free registration but you must deposit 1500 refundable security deposit for software activation key.",
    "Amazon VIP task partner program. Recharge your wallet with 2000 INR to unlock VIP task level 1 and get 30% instant commission payout in your bank account or USDT crypto wallet.",
    "Offer Letter: Appointed as Senior Cloud Architect at Google India. CTC 36 LPA. You must surrender your original 10th and 12th marksheet certificates and submit 2 blank signed cheques for bond verification.",
    "Urgent requirement for online movie review assistant. Daily payout 5000 Rs directly to PhonePe or GPay. Send screenshot of your Aadhaar card and bank account login to HR on Telegram.",
    "Immediate joining for Flipkart remote customer support. Registration charge of 1200 INR must be paid via Google Pay before appointment letter can be issued. Limited seats left, offer valid today only.",
    "Prepaid crypto task mission. Deposit funds into assigned Binance account to boost merchant ratings and receive 40% immediate withdrawal bonus. Contact administrator on Telegram group."
]

def train_and_export():
    texts = AUTHENTIC_SAMPLES + FRAUDULENT_SAMPLES
    labels = [0] * len(AUTHENTIC_SAMPLES) + [1] * len(FRAUDULENT_SAMPLES)

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), stop_words='english', min_df=1)),
        ('clf', LogisticRegression(C=1.0, random_state=42))
    ])

    pipeline.fit(texts, labels)

    output_dir = os.path.dirname(__file__)
    model_path = os.path.join(output_dir, "scam_classifier.pkl")
    joblib.dump(pipeline, model_path)
    print(f"Model successfully trained and saved to {model_path}")

if __name__ == "__main__":
    train_and_export()
