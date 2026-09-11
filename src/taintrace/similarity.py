"""Similarity algorithms for package name comparison."""

from typing import List, Tuple


class SimilarityEngine:
    """Calculate similarity between package names using multiple algorithms."""

    def similarity(self, name1: str, name2: str) -> float:
        """Combined similarity score (0.0 to 1.0)."""
        if name1 == name2:
            return 1.0

        # Levenshtein-based similarity
        lev_score = self._levenshtein_similarity(name1, name2)
        
        # Phonetic similarity using Soundex
        phonetic_score = self._phonetic_similarity(name1, name2)
        
        # Substring matching
        substring_score = self._substring_similarity(name1, name2)
        
        # Weighted combination
        return max(lev_score * 0.6 + phonetic_score * 0.2 + substring_score * 0.2, 
                   lev_score, phonetic_score, substring_score)

    def levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Normalized Levenshtein similarity (1.0 = identical)."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        dist = self.levenshtein(s1, s2)
        return 1.0 - (dist / max_len)

    def _phonetic_similarity(self, s1: str, s2: str) -> float:
        """Phonetic similarity using Soundex."""
        sx1 = self._soundex(s1)
        sx2 = self._soundex(s2)
        if sx1 == sx2:
            return 1.0
        # Partial match
        matches = sum(1 for a, b in zip(sx1, sx2) if a == b)
        return matches / max(len(sx1), len(sx2))

    def _soundex(self, s: str) -> str:
        """Simple Soundex implementation."""
        if not s:
            return ""
        s = s.lower()
        soundex_map = {
            'b': '1', 'f': '1', 'p': '1', 'v': '1',
            'c': '2', 'g': '2', 'j': '2', 'k': '2', 
            'q': '2', 's': '2', 'x': '2', 'z': '2',
            'd': '3', 't': '3',
            'l': '4',
            'm': '5', 'n': '5',
            'r': '6'
        }
        result = [s[0]]
        prev_code = ''
        for char in s[1:]:
            code = soundex_map.get(char, '')
            if code and code != prev_code:
                result.append(code)
                prev_code = code
            if len(result) == 4:
                break
        return ''.join(result).ljust(4, '0')

    def _substring_similarity(self, s1: str, s2: str) -> float:
        """Check if one string contains the other."""
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        if s1_lower in s2_lower or s2_lower in s1_lower:
            shorter = min(len(s1), len(s2))
            longer = max(len(s1), len(s2))
            return shorter / longer if longer > 0 else 1.0
        return 0.0
