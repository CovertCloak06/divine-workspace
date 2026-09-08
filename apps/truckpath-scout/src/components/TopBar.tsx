import { Link, useNavigate } from 'react-router-dom';
import type { ReactNode } from 'react';

interface Props {
  title: string;
  back?: string | true;
  right?: ReactNode;
}

export default function TopBar({ title, back, right }: Props) {
  const navigate = useNavigate();
  return (
    <header className="no-print sticky top-0 z-[1100] flex items-center gap-2 bg-panel border-b border-edge px-3 py-2 min-h-[56px]">
      {back ? (
        <button
          className="btn-secondary !px-3 shrink-0"
          onClick={() => (back === true ? navigate(-1) : navigate(back))}
          aria-label="Back"
        >
          ←
        </button>
      ) : (
        <Link to="/" className="text-xl shrink-0" aria-label="Home">
          🚛
        </Link>
      )}
      <h1 className="flex-1 text-lg font-bold truncate">{title}</h1>
      {right}
    </header>
  );
}
