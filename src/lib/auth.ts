import {apiFetch} from "./api";
import {getCSRFToken} from "./csrf"

const BASE_URL = "http://localhost:8000/api/auth";

export async function signup(data:{
    email: string,
    username: string,
    password: string,
}){
    return apiFetch(`${BASE_URL}/signup/`,{
        method: "POST",
        headers: {
            "X-CSRFToken": getCSRFToken(),
        },
        body: JSON.stringify(data),
    });
}


export async function login(data:{
    email: string,
    password: string
}){
    return apiFetch(`${BASE_URL}/login/`,{
        method: "POST",
        headers: {
            "X-CSRFToken": getCSRFToken()
        },
        body: JSON.stringify(data),
    });
}

export async function verifyOTP(data:{
    email: string,
    otp: string
}){
    return apiFetch(`${BASE_URL}/verify-login-otp/`,{
        method: "POST",
        headers:{
            "X-CSRFToken": getCSRFToken()
        },
        body: JSON.stringify(data),
    });
}

export async function logout(){
    return apiFetch(`${BASE_URL}/logout/`,{
        method: "POST",
        headers: {
            "X-CSRFToken": getCSRFToken(),
        },
    });
}