import Link from "next/link";


export default function Footer() {
  return (
    <footer className="py-8 bg-white border-t border-gray-100 text-gray-700">
      <div className="max-w-7xl mx-auto px-6 flex justify-between items-center">
        <p>© 2026 Instagram. All rights reserved.</p>

        <div className="flex gap-6">
          <Link href="#">Privacy</Link>
          <Link href="#">Terms</Link>
          <Link href="#">GitHub</Link>

        </div>

      </div>

    </footer>
  );
}
