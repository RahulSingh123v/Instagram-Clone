"use client"

import {useState} from "react";
import {signup} from "@/lib/auth";
import {useRouter} from "next/navigation";

export default function SignupForm(){
    const router = useRouter();

    const[form,setForm] = useState({
        email: "",
        username: "",
        password: "",
    });
    const[loading,setLoading] = useState(false);
    const[error, setError] = useState("");

    async function handleSubmit(e: React.FormEvent){
        e.preventDefault();
        setLoading(true);


        try{
            setError("");
            const res = await signup(form);

            if(!res.ok){
                const data = await res.json().catch(() => ({}));
                // The backend DRF might return an object with arrays of errors, e.g. { username: ["username is already taken"] }
                // Let's extract the first error message we can find
                let errorMessage = "Something went wrong";
                if (data.error) {
                    errorMessage = data.error;
                } else if (typeof data === 'object' && Object.keys(data).length > 0) {
                    const firstKey = Object.keys(data)[0];
                    if (Array.isArray(data[firstKey])) {
                        errorMessage = data[firstKey][0];
                    }
                }
                throw new Error(errorMessage);
            }
            router.push(`/verify?email=${form.email}`);

        }
        catch(err: any){
            setError(err.message || "Something went wrong");
        }
        finally{
            setLoading(false);
        }
    }
 
    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <input
            type="email"
            placeholder="Email"
            className="w-full border border-gray-300 rounded-xl p-3 text-gray-900 placeholder-gray-400 outline-none focus:ring-2 focus:ring-purple-500"
            onChange={(e) => 
                setForm({...form,email: e.target.value})
            }
            />
            <input
            type="text"
            placeholder="Username"
            className="w-full border border-gray-300 rounded-xl p-3 text-gray-900 placeholder-gray-400 outline-none focus:ring-2 focus:ring-purple-500"
            onChange={(e) =>
                setForm({...form,username: e.target.value})
            }
            />
            <input
            type="password"
            placeholder="Password"
            className="w-full border border-gray-300 rounded-xl p-3 text-gray-900 placeholder-gray-400 outline-none focus:ring-2 focus:ring-purple-500"
            onChange={(e) =>
                setForm({...form, password:e.target.value})
            }
            />
            {error && (
                <p className="text-sm text-red-500">{error}</p>
            )}
            <button
            disabled={loading}
            className="w-full py-3 rounded-xl bg-linear-to-r from-orange-500 to-purple-600 text-white"
            >
                {loading ? "Loading...":"Create Account"}
            </button>
        </form>

    );
}