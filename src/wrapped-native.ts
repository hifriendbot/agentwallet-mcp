/**
 * Wrapped-native (WETH9-style) token per EVM chain. Shared by the wrap_eth and
 * unwrap_eth tools and by the local token cap, which prices deposit() and
 * withdraw(uint256) only when they are aimed at this exact contract.
 */
export const WRAPPED_NATIVE: Record<number, { address: string; symbol: string }> = {
  1:       { address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', symbol: 'WETH' },
  8453:    { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  42161:   { address: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', symbol: 'WETH' },
  10:      { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  137:     { address: '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270', symbol: 'WPOL' },
  56:      { address: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', symbol: 'WBNB' },
  43114:   { address: '0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7', symbol: 'WAVAX' },
  7777777: { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  369:     { address: '0xA1077a294dDE1B09bB078844df40758a5D0f9a27', symbol: 'WPLS' },
};

/** Lowercased wrapped-native address for `chainId`, or undefined when none is configured. */
export function wrappedNativeAddress(chainId: number): string | undefined {
  return WRAPPED_NATIVE[chainId]?.address.toLowerCase();
}
