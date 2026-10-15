using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using MiniWireshark.Models;

namespace MiniWireshark.Core.Filtering;

/// <summary>Erreur de syntaxe ou de champ inconnu dans une expression de filtre display.</summary>
public sealed class DisplayFilterException : Exception
{
    public DisplayFilterException(string message) : base(message)
    {
    }
}

internal enum TokenType { Field, Number, String, Op, And, Or, Not, LParen, RParen, Eof }

internal readonly record struct Token(TokenType Type, string Text);

/// <summary>Découpe une expression de filtre en tokens. Un token "valeur" commence par un chiffre ou un guillemet ; un token "champ" commence par une lettre.</summary>
internal static class Tokenizer
{
    public static List<Token> Tokenize(string input)
    {
        var tokens = new List<Token>();
        int i = 0;

        while (i < input.Length)
        {
            char c = input[i];

            if (char.IsWhiteSpace(c)) { i++; continue; }

            if (c == '(') { tokens.Add(new Token(TokenType.LParen, "(")); i++; continue; }
            if (c == ')') { tokens.Add(new Token(TokenType.RParen, ")")); i++; continue; }

            if (c == '=' && Peek(input, i + 1) == '=') { tokens.Add(new Token(TokenType.Op, "==")); i += 2; continue; }
            if (c == '!' && Peek(input, i + 1) == '=') { tokens.Add(new Token(TokenType.Op, "!=")); i += 2; continue; }
            if (c == '>' && Peek(input, i + 1) == '=') { tokens.Add(new Token(TokenType.Op, ">=")); i += 2; continue; }
            if (c == '<' && Peek(input, i + 1) == '=') { tokens.Add(new Token(TokenType.Op, "<=")); i += 2; continue; }
            if (c == '>') { tokens.Add(new Token(TokenType.Op, ">")); i++; continue; }
            if (c == '<') { tokens.Add(new Token(TokenType.Op, "<")); i++; continue; }

            if (c == '&' && Peek(input, i + 1) == '&') { tokens.Add(new Token(TokenType.And, "&&")); i += 2; continue; }
            if (c == '|' && Peek(input, i + 1) == '|') { tokens.Add(new Token(TokenType.Or, "||")); i += 2; continue; }
            if (c == '!') { tokens.Add(new Token(TokenType.Not, "!")); i++; continue; }

            if (c == '"')
            {
                int start = i + 1;
                int end = input.IndexOf('"', start);
                if (end < 0)
                    throw new DisplayFilterException("Guillemet fermant manquant dans l'expression.");
                tokens.Add(new Token(TokenType.String, input.Substring(start, end - start)));
                i = end + 1;
                continue;
            }

            if (char.IsLetter(c) || c == '_')
            {
                int start = i;
                while (i < input.Length && (char.IsLetterOrDigit(input[i]) || input[i] == '_' || input[i] == '.'))
                    i++;
                string word = input.Substring(start, i - start);

                switch (word.ToLowerInvariant())
                {
                    case "and": tokens.Add(new Token(TokenType.And, word)); continue;
                    case "or": tokens.Add(new Token(TokenType.Or, word)); continue;
                    case "not": tokens.Add(new Token(TokenType.Not, word)); continue;
                    default: tokens.Add(new Token(TokenType.Field, word)); continue;
                }
            }

            if (char.IsDigit(c))
            {
                int start = i;
                // Suffisamment permissif pour couvrir entiers, hex (0x...), adresses IP (1.2.3.4) et MAC (aa:bb:cc:dd:ee:ff)
                while (i < input.Length && (char.IsLetterOrDigit(input[i]) || input[i] == '.' || input[i] == ':'))
                    i++;
                tokens.Add(new Token(TokenType.Number, input.Substring(start, i - start)));
                continue;
            }

            throw new DisplayFilterException($"Caractère inattendu dans le filtre : '{c}'");
        }

        tokens.Add(new Token(TokenType.Eof, string.Empty));
        return tokens;
    }

    private static char Peek(string s, int i) => i < s.Length ? s[i] : '\0';
}

internal abstract class FilterNode
{
    public abstract bool Evaluate(CapturedPacket packet);
}

internal sealed class AndNode(FilterNode left, FilterNode right) : FilterNode
{
    public override bool Evaluate(CapturedPacket packet) => left.Evaluate(packet) && right.Evaluate(packet);
}

internal sealed class OrNode(FilterNode left, FilterNode right) : FilterNode
{
    public override bool Evaluate(CapturedPacket packet) => left.Evaluate(packet) || right.Evaluate(packet);
}

internal sealed class NotNode(FilterNode inner) : FilterNode
{
    public override bool Evaluate(CapturedPacket packet) => !inner.Evaluate(packet);
}

/// <summary>Champ seul, sans opérateur (ex: "tcp", "arp", "tcp.flags.syn") : un simple test de présence/vérité.</summary>
internal sealed class PresenceNode(FieldDescriptor descriptor) : FilterNode
{
    public override bool Evaluate(CapturedPacket packet)
    {
        var value = descriptor.Accessor(packet);
        return descriptor.Kind switch
        {
            FieldKind.Protocol => value is true,
            FieldKind.Flag => value is true,
            FieldKind.NumberList => value is long[] { Length: > 0 },
            FieldKind.StringList => value is string[] { Length: > 0 },
            _ => value != null
        };
    }
}

/// <summary>Comparaison champ/opérateur/valeur (ex: "tcp.port == 443").</summary>
internal sealed class ComparisonNode(FieldDescriptor descriptor, string op, string rawValue, string fieldName) : FilterNode
{
    public override bool Evaluate(CapturedPacket packet)
    {
        var value = descriptor.Accessor(packet);
        if (value is null)
            return false; // champ absent du paquet (couche non présente) => ne correspond jamais, comme dans Wireshark

        switch (descriptor.Kind)
        {
            case FieldKind.Number:
                return CompareNumbers(op, (long)value, ParseIntLiteral(rawValue));

            case FieldKind.NumberList:
                var right = ParseIntLiteral(rawValue);
                return ((long[])value).Any(v => CompareNumbers(op, v, right));

            case FieldKind.Flag:
                bool leftFlag = (bool)value;
                bool rightFlag = ParseBoolLiteral(rawValue);
                return op switch
                {
                    "==" => leftFlag == rightFlag,
                    "!=" => leftFlag != rightFlag,
                    _ => throw new DisplayFilterException($"L'opérateur '{op}' n'est pas supporté sur un indicateur (flag) comme '{fieldName}'.")
                };

            case FieldKind.String:
                return CompareStrings(op, (string)value, rawValue);

            case FieldKind.StringList:
                return ((string[])value).Any(v => CompareStrings(op, v, rawValue));

            default:
                throw new DisplayFilterException($"Le champ '{fieldName}' ne supporte pas de comparaison — utilise-le seul (ex: '{fieldName}').");
        }
    }

    private static bool CompareStrings(string op, string left, string rawRight)
    {
        string right = rawRight.Trim('"');
        bool eq = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        return op switch
        {
            "==" => eq,
            "!=" => !eq,
            _ => throw new DisplayFilterException($"L'opérateur '{op}' n'est pas supporté sur un champ texte/adresse.")
        };
    }

    private static bool CompareNumbers(string op, long left, long right) => op switch
    {
        "==" => left == right,
        "!=" => left != right,
        ">" => left > right,
        "<" => left < right,
        ">=" => left >= right,
        "<=" => left <= right,
        _ => throw new DisplayFilterException($"Opérateur numérique inconnu : '{op}'")
    };

    private static long ParseIntLiteral(string text)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (long.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
                return hex;
        }
        else if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
        {
            return dec;
        }

        throw new DisplayFilterException($"'{text}' n'est pas un nombre valide (entier décimal ou hexadécimal 0x...).");
    }

    private static bool ParseBoolLiteral(string text) => text.Trim().ToLowerInvariant() switch
    {
        "1" or "true" => true,
        "0" or "false" => false,
        _ => throw new DisplayFilterException($"'{text}' n'est pas une valeur booléenne valide (attendu 0, 1, true ou false).")
    };
}

/// <summary>Parseur récursif descendant : OrExpr := AndExpr ('or' AndExpr)* ; AndExpr := UnaryExpr ('and' UnaryExpr)* ; UnaryExpr := 'not' UnaryExpr | Primary.</summary>
internal sealed class Parser(List<Token> tokens)
{
    private int _pos;

    private Token Current => tokens[_pos];

    public FilterNode ParseExpression() => ParseOr();

    public void ExpectEof()
    {
        if (Current.Type != TokenType.Eof)
            throw new DisplayFilterException($"Caractère(s) inattendu(s) en fin de filtre, près de '{Current.Text}'.");
    }

    private FilterNode ParseOr()
    {
        var left = ParseAnd();
        while (Current.Type == TokenType.Or)
        {
            _pos++;
            var right = ParseAnd();
            left = new OrNode(left, right);
        }
        return left;
    }

    private FilterNode ParseAnd()
    {
        var left = ParseUnary();
        while (Current.Type == TokenType.And)
        {
            _pos++;
            var right = ParseUnary();
            left = new AndNode(left, right);
        }
        return left;
    }

    private FilterNode ParseUnary()
    {
        if (Current.Type == TokenType.Not)
        {
            _pos++;
            return new NotNode(ParseUnary());
        }
        return ParsePrimary();
    }

    private FilterNode ParsePrimary()
    {
        if (Current.Type == TokenType.LParen)
        {
            _pos++;
            var inner = ParseOr();
            if (Current.Type != TokenType.RParen)
                throw new DisplayFilterException("Parenthèse fermante ')' manquante.");
            _pos++;
            return inner;
        }

        if (Current.Type == TokenType.Field)
        {
            string fieldName = Current.Text;
            _pos++;

            if (!FieldRegistry.Fields.TryGetValue(fieldName, out var descriptor))
            {
                var suggestions = string.Join(", ", FieldRegistry.Fields.Keys.OrderBy(k => k));
                throw new DisplayFilterException($"Champ inconnu : '{fieldName}'. Champs disponibles : {suggestions}.");
            }

            if (Current.Type == TokenType.Op)
            {
                string op = Current.Text;
                _pos++;

                if (Current.Type != TokenType.Number && Current.Type != TokenType.String)
                    throw new DisplayFilterException($"Une valeur est attendue après l'opérateur '{op}' (champ '{fieldName}').");

                string rawValue = Current.Text;
                _pos++;
                return new ComparisonNode(descriptor, op, rawValue, fieldName);
            }

            return new PresenceNode(descriptor);
        }

        throw new DisplayFilterException($"Expression de filtre invalide près de '{Current.Text}'.");
    }
}