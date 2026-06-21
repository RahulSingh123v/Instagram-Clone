"use client"

import { useAuth } from "@/hooks/useAuth";
import { logout } from "@/lib/auth";
import { useRouter } from "next/navigation";
import { useState } from "react";

export default function DashboardPage() {
    const { user, loading } = useAuth();
    const router = useRouter();
    const [loggingOut, setLoggingOut] = useState(false);

    async function handleLogout() {
        setLoggingOut(true);
        try {
            await logout();
        } finally {
            router.push("/login");
        }
    }

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p className="text-gray-500">Loading...</p>
            </div>
        );
    }

    if (!user) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p className="text-gray-500">Unauthorized</p>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-50">
            {/* Top navbar */}
            <header className="bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
                <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
                <button
                    onClick={handleLogout}
                    disabled={loggingOut}
                    className="px-4 py-2 rounded-lg bg-red-500 text-white text-sm font-medium hover:bg-red-600 transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {loggingOut ? "Logging out..." : "Logout"}
                </button>
            </header>

            {/* Content */}
            <main className="p-10">
                <h2 className="text-3xl font-bold text-gray-900">
                    Welcome, {user.username} 👋
                </h2>
                <p className="text-gray-500 mt-2">{user.email}</p>
            </main>
        </div>
    );
}