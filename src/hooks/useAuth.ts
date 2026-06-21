"use client";

import {useCallback,useEffect, useState} from "react";
import { apiFetch } from "@/lib/api";

type User = {
    id: number;
    username: string;
    email: string;
}

type UseAuthReturn = {
    user: User | null;
    loading: boolean;
    error: string | null;
    isAuthenticated: boolean;
    refetchUser: () => Promise<void>;
}


export function useAuth(){
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const[error,setError] = useState<string | null>(null)


    const fetchUser = useCallback(async () => {
        let isMounted = true;
        
        try{
            setError(null);
            
            const res = await apiFetch(
                "http://localhost:8000/api/auth/me/"
            );

            if(!res.ok){
                if(isMounted){
                    setUser(null);
                }
                return;
                
            }
            const data = await res.json();
            if(isMounted){
                setUser(data);
            }
        }
        catch(err){
            if(isMounted){
                setUser(null);
                setError("Something went wrong");
            }
        }
        finally{
            if(isMounted){
                setLoading(false);
            }
        }
    }, []);

    useEffect(() => {
        fetchUser();
    }, [fetchUser]);

    return {
        user,
        loading,
        error,
        isAuthenticated: !!user,
        refetchUser: fetchUser,
    };


}