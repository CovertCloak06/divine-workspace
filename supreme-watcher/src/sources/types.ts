/** A normalized product listing, source-agnostic. */
export interface Listing {
  /** Stable unique id within the source (Supreme product id). */
  id: string;
  name: string;
  category: string;
  /** Price in USD (already converted from the source's units). */
  price: number;
  soldOut: boolean;
  imageUrl?: string;
  /** Direct link to the product page. */
  url: string;
}

/** A marketplace adapter. Add new marketplaces by implementing this. */
export interface Source {
  /** Human-readable name, e.g. "Supreme (US)". */
  readonly name: string;
  /** Fetch the current full catalog of listings. */
  fetchListings(): Promise<Listing[]>;
}
