# ⚙️ Digital Life Lessons | MERN Stack Backend (Server Side)

<p align="center">
  <img src="https://i.ibb.co/XrVnrMk4/Screenshot-2026-01-20-130139.png" alt="Care Project Main Banner" width="100%">
</p>

### 🚀 [Live Client Demo](https://digital-lifes-lesson.netlify.app)
### 💻 [Client Side Repository](https://github.com/sabbir019777/assignment-11-client-side.git)

---

## 📝 Backend Overview
This is the **Server Side** of the Digital Life Lessons application. It provides a robust and secure RESTful API to manage user authentication, premium memberships via Stripe, and full CRUD operations for life lessons stored in MongoDB.

## 📱 Mobile Responsiveness
<p align="center">
  <img src="https://i.ibb.co/mrJZ82J3/Screenshot-2026-01-20-130119.png" alt="Care Project Mobile View" width="300px">
</p>

## 🛠️ Main Technologies Used (Backend)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![Stripe API](https://img.shields.io/badge/Stripe_API-626CD9?style=for-the-badge&logo=stripe&logoColor=white)
![Firebase Admin](https://img.shields.io/badge/Firebase_Admin-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)
![Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)

## ✨ Key Backend Features
* **RESTful API Design:** Clean and structured endpoints for all resources.
* **Authentication & Authorization:** Verifies Firebase ID tokens using **Firebase Admin SDK**.
* **Payment Integration:** Securely handles one-time payments through **Stripe Checkout and Webhooks**.
* **Role-Based Access Control:** Protects Admin and Premium routes from unauthorized access.
* **Database Management:** Efficient data handling and relationship management with **MongoDB Atlas**.

## 📦 Major Dependencies
* `express`
* `mongodb`
* `stripe`
* `firebase-admin`
* `dotenv` (for securing credentials)
* `cors`

## 🚀 Deployment
* **Client:** Netlify
* **Server:** Vercel
* **Database:** MongoDB Atlas

## 🚀 How to Run Locally

1. **Clone the repository:**
`git clone https://github.com/sabbir019777/assignment-11-server-side.git`

2. **Install dependencies:**
`npm install`

3. **Configure Environment Variables:**
Create a `.env` file and add your `STRIPE_SECRET_KEY`, `MONGODB_URI`, and Firebase service account details.

4. **Start the server:**
`npm start` or `nodemon index.js`

---

## 👤 Author
**Tamim Iqbal**  
MERN-Stack Web 
Developer
