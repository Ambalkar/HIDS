import os
import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score
import joblib
from loguru import logger

def load_data():
    """Load and prepare the dataset for evaluation."""
    try:
        df = pd.read_csv(os.path.join('data', 'cybersecurity_attacks.csv'))
        
        # Prepare features and target
        categorical = ['Protocol', 'Attack Type']
        features = ['Source Port', 'Destination Port', 'Packet Length', 'Protocol']
        
        # Load the same encoders used in training
        encoders = joblib.load(os.path.join('models', 'ids_encoders.joblib'))
        
        # Transform categorical variables
        for col in categorical:
            if col in df.columns and col in encoders:
                df[col] = encoders[col].transform(df[col].astype(str))
        
        # Prepare X and y
        X = df[features].fillna(0)
        y = (df['Attack Type'].notna().astype(int) if 'Attack Type' in df.columns else np.zeros(len(df)))
        
        return X, y
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        raise

def evaluate_model():
    """Evaluate the model and calculate accuracy scores."""
    try:
        # Load data
        X, y = load_data()
        
        # Load the trained model and scaler
        model = joblib.load(os.path.join('models', 'ids_rf_model.joblib'))
        scaler = joblib.load(os.path.join('models', 'ids_scaler.joblib'))
        
        # Scale the features
        X_scaled = scaler.transform(X)
        
        # Perform cross-validation
        cv_scores = cross_val_score(model, X_scaled, y, cv=5)
        
        # Split data for final accuracy calculation
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        # Train on training set and predict on test set
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        # Calculate accuracy scores
        test_accuracy = accuracy_score(y_test, y_pred)
        mean_cv_accuracy = cv_scores.mean()
        
        # Print results
        print("\nModel Accuracy Results:")
        print("=" * 50)
        print(f"\nCross-validation accuracy scores (5-fold):")
        for i, score in enumerate(cv_scores, 1):
            print(f"Fold {i}: {score:.2%}")
        
        print(f"\nMean cross-validation accuracy: {mean_cv_accuracy:.2%}")
        print(f"Test set accuracy: {test_accuracy:.2%}")
        
        # Save results to file
        os.makedirs('evaluation_results', exist_ok=True)
        with open(os.path.join('evaluation_results', 'accuracy_results.txt'), 'w') as f:
            f.write("Model Accuracy Results\n")
            f.write("=" * 50 + "\n\n")
            f.write("Cross-validation accuracy scores (5-fold):\n")
            for i, score in enumerate(cv_scores, 1):
                f.write(f"Fold {i}: {score:.2%}\n")
            f.write(f"\nMean cross-validation accuracy: {mean_cv_accuracy:.2%}\n")
            f.write(f"Test set accuracy: {test_accuracy:.2%}\n")
        
        logger.info("Model accuracy evaluation completed. Results saved in 'evaluation_results/accuracy_results.txt'")
        
    except Exception as e:
        logger.error(f"Error during model evaluation: {e}")
        raise

if __name__ == "__main__":
    evaluate_model() 