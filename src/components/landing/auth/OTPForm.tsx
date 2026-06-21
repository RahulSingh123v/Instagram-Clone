"use client"

import {useSearchParams, useRouter} from "next/navigation";
import {useState} from "react";
import {verifyOTP} from"@/lib/auth";


export default function OTPForm(){

    const params = useSearchParams();
    const router = useRouter();

    const email = params.get("email") || "";

    const[otp,setOtp] = useState("");
    const[loading,setLoading] = useState(false);
    const[error,setError] = useState("")

    async function handleSubmit(e: React.FormEvent){

        e.preventDefault();

        setError("");

        if (!otp.trim()){
            setError("OTP is required")
            return
        }

        if(otp.length != 6){
            setError("otp must be 6 digits")
            return
        }

        try{
            setLoading(true);

            const res = await verifyOTP({
                email,
                otp
            });

            if(!res.ok){
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || "Invalid otp");
            }
            router.push(`/dashboard`);
        }
        catch(err: any){
            setError(err.message || "Something went wrong. Please try again.");
            console.log(err)
        }
        finally{
            setLoading(false);
        }

    }

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <div>
                <input
                type="text"
                inputMode="numeric"
                maxLength = {6}
                value = {otp}
                onChange={(e) => 
                    setOtp(e.target.value.replace(/\D/g,""))
                }
                placeholder="Enter 6-digit OTP"
                className="w-full text-gray-600 vorder border-gray-300 rounded-xl p-3 outline-none focus:ring-2 focus:ring-purple-500"
                />
                {error && (
                    <p className="mt-2 text-sm text-red-500">
                        {error}
                    </p>
                )}
            </div>

            <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-purple-600 text-white font-medium transition hoover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {loading ? "Verifying..." : "Verify Otp"}
            </button>

        </form>
    );
}   
