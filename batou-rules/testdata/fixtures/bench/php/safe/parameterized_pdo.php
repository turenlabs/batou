<?php
declare(strict_types=1);

// SAFE: PDO prepared statement with named placeholders
function findUserById(PDO $pdo, string $id): ?array {
    $stmt = $pdo->prepare(
        'SELECT id, username, email FROM users WHERE id = :id AND active = 1'
    );
    $stmt->execute(['id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

// SAFE: PDO prepared statement with positional placeholders
function searchUsers(PDO $pdo, string $query, int $limit = 20): array {
    $stmt = $pdo->prepare(
        'SELECT id, username FROM users WHERE username LIKE ? ORDER BY username LIMIT ?'
    );
    $stmt->execute(['%' . $query . '%', $limit]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// SAFE: PDO prepared INSERT
function createPost(PDO $pdo, string $title, string $body, int $authorId): int {
    $stmt = $pdo->prepare(
        'INSERT INTO posts (title, body, author_id, created_at) VALUES (:title, :body, :author, NOW())'
    );
    $stmt->execute([
        'title' => $title,
        'body' => $body,
        'author' => $authorId,
    ]);
    return (int) $pdo->lastInsertId();
}

// SAFE: PDO prepared UPDATE
function updateProfile(PDO $pdo, int $userId, string $bio): void {
    $stmt = $pdo->prepare('UPDATE profiles SET bio = :bio WHERE user_id = :uid');
    $stmt->execute(['bio' => $bio, 'uid' => $userId]);
}

// SAFE: PDO prepared DELETE
function deleteComment(PDO $pdo, int $commentId, int $authorId): void {
    $stmt = $pdo->prepare('DELETE FROM comments WHERE id = ? AND author_id = ?');
    $stmt->execute([$commentId, $authorId]);
}
