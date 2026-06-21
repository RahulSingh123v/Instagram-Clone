import Image from "next/image";
import Link from "next/link";

export default function Hero() {
  return (
    <section className="relative flex-1 flex items-center py-20">
      <div className="absolute inset-0 bg-linear-to-br from-purple-200 via-white to-orange-200" />

      <div className="relative max-w-7xl mx-auto px-6 grid md:grid-cols-2 gap-12 items-center">
        
        {/* Left Content */}
        <div>
          <h1 className="text-5xl text-gray-600 md:text-6xl font-bold leading-tight">
            Share Moments. <br />
            Connect Instantly.
          </h1>

          <p className="mt-6 text-lg text-gray-600 max-w-lg">
            A simple, fast, and beautiful way to share your life with friends.
          </p>

          <div className="mt-8 flex gap-4">
            <Link
              href="/signup"
              className="px-6 py-3 rounded-xl bg-linear-to-r from-orange-500 to-purple-600 text-white font-semibold shadow-lg hover:opacity-90 transition"
            >
              Create Account
            </Link>

            <Link
              href="/login"
              className="px-6 py-3 rounded-xl border text-gray-700 border-gray-800 hover:bg-gray-300 transition"
            >
              Login
            </Link>
          </div>
        </div>

        {/* Right Image */}
        <div className="flex justify-center">
          <div className="relative w-300 h-137.5 rounded-3xl shadow-1-2xl overflow-hidden border border-gray-200 bg-black">
            <Image
              src="/phone2.jpg"
              alt="App preview"
              fill
              className="object-cover"
            />
          </div>
        </div>

      </div>
    </section>
  );
}
