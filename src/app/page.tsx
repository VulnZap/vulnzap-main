import { Header } from "@/components/layout/header";
import { Footer } from "@/components/layout/footer";
import { Hero } from "@/components/sections/hero";
import { Features } from "@/components/sections/features";
import { Ecosystems } from "@/components/sections/ecosystems";
import { Pricing } from "@/components/sections/pricing";

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-grow">
        <Hero />
        <Features />
        <Ecosystems />
        <Pricing />
      </main>
      <Footer />
    </div>
  );
} 